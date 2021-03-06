#!/usr/bin/env python3

# берет события в формате etvx (их можно скачать также с помощью sysmon в просмотре событий)
# просмотр событий windows -> журналы приложений и служб -> Microsoft -> Windows -> Sysmon
# отсюда можно эспортировать события в etvx

# далее тут реализован класс который характеризует каждый процесс
# т е один процесс - это экземпляр класса

# класс преобразовывает etvx в xml

# ВАЖНО при любой реализации из файла xml sysmon необходимо удалять текст в начале, а именно:
# xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event

# в классе реализован метод который восстанавливает иерархию (но пока только для двух типов событий sysmon id = 1 и sysmon id = 5)
import logging
import datetime
from collections import namedtuple

import pytz

import json
import iso8601
from lxml import etree
from lxml.etree import XMLSyntaxError

from Evtx.Evtx import Evtx
from Evtx.Views import evtx_file_xml_view


g_logger = logging.getLogger("process-forest.global")


def to_lxml(record_xml):
    """
    @type record: Record
    """
    utf8_parser = etree.XMLParser(encoding='utf-8')
    return etree.fromstring("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\" ?>%s" %
            record_xml.replace("xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"", "").encode('utf-8'), parser=utf8_parser)


class Process(object):
    NOTE_FAKE_PARENT = "Fake Parent: This is a faked process created since a ppid didn't exist"
    NOTE_END_LOST = "Lost End Timestamp: This end timestamp is suspect, because it collided with another process"
    def __init__(self, pid, ppid, cmdline, ppname, hashes, path, user, domain, logonid, computer,
            pid_formatter=str):
        super(Process, self).__init__()
        self.pid = pid
        self.ppid = ppid
        self.path = path
        self.cmdline = cmdline
        self.ppname = ppname
        self.hashes = hashes
        self.user = user
        self.domain = domain
        self.logonid = logonid
        self.computer = computer
        self.begin = datetime.datetime.min
        self.end = datetime.datetime.min
        self.parent = None
        self.children = []
        self.notes = None
        self.id = None  # set by analyzer, unique with analyzer session
        self.pid_formatter = pid_formatter

    def __str__(self):
        return "%s, cmd=%s, hashes=%s, pid=%s, ppid=%s, begin=%s, end=%s" % (
                self.path, self.cmdline, self.hashes,
                self.pid_formatter(self.pid), self.pid_formatter(self.ppid),
                self.begin.isoformat(), self.end.isoformat())

    # TODO: move serialize, deserialize here


def create_fake_parent_process(pid, name, pid_formatter=str):
    p = Process(pid, 0, "UNKNOWN", "UNKNOWN", "UNKNOWN", name, "UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN",
            pid_formatter=pid_formatter)
    p.notes = Process.NOTE_FAKE_PARENT
    return p


class NotAProcessEventError(Exception):
    pass


class Entry(object):
    def __init__(self, xml, record, pid_formatter=str):
        super(Entry, self).__init__()
        self._xml = xml
        self._record = record
        self._node = to_lxml(self._xml)
        self._logger = logging.getLogger("process-forest.Entry")
        self.pid_formatter = pid_formatter

    def get_xpath(self, path):
        return self._node.xpath(path)[0]

    def get_eid(self):
        return int(self.get_xpath("/Event/System/EventID").text)

    def get_timestamp(self):
        return self._record.timestamp()

    def is_process_created_event(self):
        return self.get_eid() == 4688

    def is_process_exited_event(self):
        return self.get_eid() == 4689

    def is_sysmon_proc_created_event(self):
        return self.get_eid() == 1

    def is_sysmon_proc_exited_event(self):
        return self.get_eid() == 5

    def get_process_from_4688_event(self):
        path = self.get_xpath("/Event/EventData/Data[@Name='NewProcessName']").text
        pid = int(self.get_xpath("/Event/EventData/Data[@Name='NewProcessId']").text, 0x10)
        ppid = int(self.get_xpath("/Event/EventData/Data[@Name='ProcessId']").text, 0x10)
        try:
            cmdline = self.get_xpath("/Event/EventData/Data[@Name='CommandLine']").text
        except:
            cmdline = "UNKNOWN"
        try:
            ppname = self.get_xpath("/Event/EventData/Data[@Name='ParentProcessName']").text
        except:
            ppname = "UNKNOWN"
        hashes = "UNKNOWN"
        user = self.get_xpath("/Event/EventData/Data[@Name='SubjectUserName']").text
        domain = self.get_xpath("/Event/EventData/Data[@Name='SubjectDomainName']").text
        logonid = self.get_xpath("/Event/EventData/Data[@Name='SubjectLogonId']").text
        computer = self.get_xpath("/Event/System/Computer").text
        p = Process(pid, ppid, cmdline, ppname, hashes, path, user, domain, logonid, computer,
                pid_formatter=self.pid_formatter)
        p.begin = self._record.timestamp()
        return p

    def get_process_from_4689_event(self):
        path = self.get_xpath("/Event/EventData/Data[@Name='ProcessName']").text
        pid = int(self.get_xpath("/Event/EventData/Data[@Name='ProcessId']").text, 0x10)
        ppid = int(self.get_xpath("/Event/System/Execution").get("ProcessID"), 10)
        cmdline = "UNKNOWN"
        ppname = "UNKNOWN"
        hashes = "UNKNOWN"
        user = self.get_xpath("/Event/EventData/Data[@Name='SubjectUserName']").text
        domain = self.get_xpath("/Event/EventData/Data[@Name='SubjectDomainName']").text
        logonid = self.get_xpath("/Event/EventData/Data[@Name='SubjectLogonId']").text
        computer = self.get_xpath("/Event/System/Computer").text
        p = Process(pid, ppid, cmdline, ppname, hashes, path, user, domain, logonid, computer,
                pid_formatter=self.pid_formatter)
        p.end = self._record.timestamp()
        return p

    def get_process_from_1_event(self):
        path = self.get_xpath("/Event/EventData/Data[@Name='Image']").text
        pid = int(self.get_xpath("/Event/EventData/Data[@Name='ProcessId']").text, 0x10)
        ppid = int(self.get_xpath("/Event/EventData/Data[@Name='ParentProcessId']").text, 0x10)
        cmdline = self.get_xpath("/Event/EventData/Data[@Name='CommandLine']").text
        ppname = self.get_xpath("/Event/EventData/Data[@Name='ParentImage']").text
        hashes = self.get_xpath("/Event/EventData/Data[@Name='Hashes']").text
        ud = self.get_xpath("/Event/EventData/Data[@Name='User']").text.split("\\")
        user = ud[1]
        domain = ud[0]
        logonid = self.get_xpath("/Event/EventData/Data[@Name='LogonId']").text
        computer = self.get_xpath("/Event/System/Computer").text
        p = Process(pid, ppid, cmdline, ppname, hashes, path, user, domain, logonid, computer,
                pid_formatter=self.pid_formatter)
        p.begin = self._record.timestamp()
        return p

    def get_process_from_5_event(self):
        path = self.get_xpath("/Event/EventData/Data[@Name='Image']").text
        pid = int(self.get_xpath("/Event/EventData/Data[@Name='ProcessId']").text, 0x10)
        ppid = 0
        cmdline = "UNKNOWN"
        ppname = "UNKNOWN"
        hashes = "UNKNOWN"
        user = "UNKNOWN"
        domain = "UNKNOWN"
        logonid = "UNKNOWN"
        computer = self.get_xpath("/Event/System/Computer").text
        p = Process(pid, ppid, cmdline, ppname, hashes, path, user, domain, logonid, computer,
                pid_formatter=self.pid_formatter)
        p.end = self._record.timestamp()
        return p

    def get_process_from_event(self):
        if self.is_process_created_event():
            return self.get_process_from_4688_event()
        elif self.is_process_exited_event():
            return self.get_process_from_4689_event()
        elif self.is_sysmon_proc_created_event():
            return self.get_process_from_1_event()
        elif self.is_sysmon_proc_exited_event():
            return self.get_process_from_5_event()
        else:
            raise NotAProcessEventError()


def get_entries(evtx):
    """
    @rtype: generator of Entry
    """
    for xml, record in evtx_file_xml_view(evtx.get_file_header()):
        try:
            yield Entry(xml, record)
        except etree.XMLSyntaxError as e:
            continue


def get_entries_with_eids(evtx, eids):
    """
    @type eids: iterable of int
    @rtype: generator of Entry
    """
    for entry in get_entries(evtx):
        if entry.get_eid() in eids:
            yield entry


class ProcessTreeAnalyzer(object):
    def __init__(self, pid_formatter=str):
        super(ProcessTreeAnalyzer, self).__init__()
        self._defs = {}
        self._roots = []
        self._logger = logging.getLogger("process-forest.analyzer")
        self.pid_formatter = pid_formatter

    def analyze(self, entries):
        """
        @type entries: iterable of Entry
        """
        open_processes = {}
        closed_processes = []
        for entry in entries:
            if entry.is_process_created_event() or entry.is_sysmon_proc_created_event():
                process = entry.get_process_from_event()
                if process.pid in open_processes:
                    self._logger.warning("collision on pid: %s", self.pid_formatter(process.pid))
                    other = open_processes[process.pid]
                    other.notes = Process.NOTE_END_LOST
                    other.end = entry.get_timestamp()
                    closed_processes.append(other)
                open_processes[process.pid] = process

                if process.ppid in open_processes:
                    process.parent = open_processes[process.ppid]
                    process.parent.children.append(process)
                else:
                    self._logger.warning("parent process %x not captured for new process %s",
                            self.pid_formatter(process.ppid), self.pid_formatter(process.pid))
                    # open a faked parent
                    process.parent = create_fake_parent_process(process.ppid, process.ppname,
                            pid_formatter=self.pid_formatter)
                    process.parent.children.append(process)
                    open_processes[process.ppid] = process.parent

            elif entry.is_process_exited_event() or entry.is_sysmon_proc_exited_event():
                process = entry.get_process_from_event()
                if process.pid in open_processes:
                    # use existing process instance, if it exists
                    existing_process = open_processes[process.pid]
                    if existing_process.notes == Process.NOTE_FAKE_PARENT:
                        # if we faked it, have to be careful not to lose the children
                        process.children = existing_process.children
                        # discard the faked entry, cause we'll have better info now
                    else:
                        process = existing_process
                    process.end = entry.get_timestamp()
                    del(open_processes[process.pid])
                    closed_processes.append(process)
                else:
                    self._logger.warning("missing start event for exiting process: %s", self.pid_formatter(process.pid))
                    # won't be able to guess parent, since it's PID may have been recycled
                    closed_processes.append(process)
            else:
                self._logger.debug("unexpected entry type: %s", entry)

        i = 0
        for process_set in [open_processes.values(), closed_processes]:
            for process in process_set:
                process.id = i
                i += 1
                self._defs[process.id] = process
                if process.parent is None:
                    self._roots.append(process.id)

        for process in self._defs.values():
            if process.parent is not None:
                process.parent = process.parent.id
            process.children = [c.id for c in process.children]

    def get_roots(self):
        """
        @rtype: list of Node
        """
        ret = []
        # TODO: move this outside analyzer
        def get_children_nodes(analyzer, node):
            # TODO: still need this hacky check?
            if isinstance(node, int):
                n = Node(node, None, [])
                p = n.get_process(analyzer)
                n.parent = p.parent
            else:
                n = node
                p = node.get_process(analyzer)
            return [Node(c, n, get_children_nodes(analyzer, c)) for c in p.children]

        for root in self._roots:
            if root is None:
                continue
            ret.append(Node(root, None, get_children_nodes(self, root)))
        return ret

    def get_processes(self):
        """
        note, Entry.parent/.children are IDs, not references to Entry instances
        @rtype: list of Entry
        """
        return self._defs.values()

    def get_process(self, id):
        return self._defs[id]

    def serialize(self, f):
        def simplify_process(process):
            return {
                "id": process.id,
                "pid": process.pid,
                "ppid": process.ppid,
                "cmdline": process.cmdline,
                "ppname": process.ppname,
                "hashes": process.hashes,
                "path": process.path,
                "user": process.user,
                "domain": process.domain,
                "logonid": process.logonid,
                "computer": process.computer,
                "begin": process.begin.isoformat(),
                "end": process.end.isoformat(),
                "parent": process.parent,
                "children": process.children,
                "notes": process.notes,
            }

        data = {
                "definitions": {p.id:simplify_process(p) for p in self._defs.values()},
                "roots": self._roots,
        }
        s = json.dumps(data)
        f.write(s.encode('utf-8'))

    def deserialize(self, f):
        s = f.read()
        data = json.loads(s)

        def complexify_process(p):
            process = Process(p["pid"], p["ppid"], p["cmdline"], p["ppname"], p["hashes"], p["path"], p["user"], p["domain"], p["logonid"], p["computer"],
                    pid_formatter=self.pid_formatter)
            process.begin = iso8601.parse_date(p["begin"]).replace(tzinfo=None)
            process.end = iso8601.parse_date(p["end"]).replace(tzinfo=None)
            process.parent = p["parent"]
            process.children = p["children"]
            process.notes = p["notes"]
            process.id = p["id"]
            return process

        self._defs = {p["id"]:complexify_process(p) for p in data["definitions"].values()}
        self._roots = data["roots"]


class Node(object):
    def __init__(self, id, parent, children):
        self._id = id
        self._parent = parent  # type: Node
        self._children = children  # type: list of Node

    def get_process(self, analyzer):
        """
        @rtype: Process
        """
        return analyzer.get_process(self._id)

    def get_children(self):
        """
        @rtype: list of Node
        """
        return self._children

    def get_parent(self):
        """
        @rtype: Node
        """
        return self._parent


def format_node(analyzer, node):
    p = node.get_process(analyzer)
    s = str(p)
    if p.notes is not None and len(p.notes) > 0:
        s += ": " + p.notes
    return s


def draw_tree(analyzer, node, indent=0):
    print("  " * indent + format_node(analyzer, node))
    for c in node.get_children():
        draw_tree(analyzer, c, indent=indent + 1)


def summarize_processes(processes):
    try:
        first_process = min(filter(lambda p:p.begin != datetime.datetime.min, processes), key=lambda p:p.begin)
        print("first event: %s" % (first_process.begin.isoformat()))
    except ValueError:
        print("first event: unknown")
    try:
        last_process = max(filter(lambda p:p.begin != datetime.datetime.min, processes), key=lambda p:p.begin)
        print("last event: %s" % (last_process.begin.isoformat()))
    except ValueError:
        print("last event: unknown")
    print("-------------------------")

    counts = {}  # map from path to count
    for process in processes:
        if process.path not in counts:
            counts[process.path] = 0
        counts[process.path] += 1

    print("path counts")
    for (path, count) in sorted(counts.items(), key=lambda p:p[1], reverse=True):
        print("  - %s: %d" % (path, count))
    print("-------------------------")

    # TODO: seems to be broken due to timezones?
    #
    #ONE_DAY = datetime.timedelta(1)
    #period = ONE_DAY
    #period_start = first_process.begin
    #ps = filter(lambda p: p.begin != datetime.datetime.min, processes)
    #
    #while period_start <= last_process.begin:
    #    period_count = 0
    #    period_end = period_start + period
    #    while len(ps) > 0 and ps[0].begin < period_end:
    #        period_count += 1
    #        p = ps.pop(0)
    #        print(p.begin.isoformat())
    #
    #    print("  - %s to %s: %d new processes" % (period_start.isoformat(), period_end.isoformat(), period_count))
    #    period_start += period


def main():
    import argparse
    logging.basicConfig(level=logging.DEBUG)
    logging.getLogger("iso8601.iso8601").setLevel(logging.WARNING)

    parser = argparse.ArgumentParser(
        description="Print the record numbers of EVTX log entries "
                    "that match the given EID.")
    parser.add_argument("input_file", type=str,
                        help="Path to the Windows EVTX file or .pt file")
    parser.add_argument("-X", "--hexpids",
        action="store_true", dest="hexpids", default=False, help="Output PID values in hexidecimal.")

    subparsers = parser.add_subparsers(dest="cmd")

    ts_parser = subparsers.add_parser("ts")
    ts_parser.add_argument("ts", type=str, default="",
                        help="iso8601 timestamp with which to filter")

    summary_parser = subparsers.add_parser("summary")

    serialize_parser = subparsers.add_parser("serialize")
    serialize_parser.add_argument("pt", type=str, default="state.pt",
                        help=".pt file to serialize parsed trees")

    args = parser.parse_args()

    if args.hexpids:
        pid_formatter = hex
    else:
        pid_formatter = str

    analyzer = ProcessTreeAnalyzer(pid_formatter=pid_formatter)
    if args.input_file.lower().endswith(".pt"):
        g_logger.info("using serialized file")
        with open(args.input_file, "rb") as f:
            analyzer.deserialize(f)
    else:
        g_logger.info("using evtx log file")
        with Evtx(args.input_file) as evtx:
            analyzer.analyze(get_entries_with_eids(evtx, set([4688, 4689, 1, 5])))
            pass

    if args.cmd == "summary":
        summarize_processes(analyzer.get_processes())
    elif args.cmd == "ts":
        if args.ts == "all":
            for root in analyzer.get_roots():
                draw_tree(analyzer, root)
        else:
            g_logger.error("query trees not yet supported")
    elif args.cmd == "serialize":
        if not args.pt.lower().endswith(".pt"):
            g_logger.error("serialize output file must have .pt extension")
        else:
            with open(args.pt, "wb") as f:
                analyzer.serialize(f)
    else:
        g_logger.error("unknown command: %s", args.cmd)


if __name__ == "__main__":
    # main()
    # get_entries_with_eids()
    # evtx = "C:\\Users\\Adele]\Desktop\\sysmon_try.evtx"
    # print(get_entries(evtx))
    evtx = Evtx("one_sysmon.evtx")
    pid_formatter = str
    analyzer = ProcessTreeAnalyzer(pid_formatter=pid_formatter)
    analyzer.analyze(get_entries_with_eids(evtx, set([4688, 4689, 1, 5])))
