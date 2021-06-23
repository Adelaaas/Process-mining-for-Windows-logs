# import win32evtlog

# # # SYSMON_XPATH_QUERY = """<QueryList><Query Id="0" Path="{event_log_path}"><Select Path="{event_log_path}">*[System[TimeCreated[@SystemTime>='{event_timestamp}']]]</Select></Query></QueryList>"""
# SYSMON_EVENT_LOG_PATH = "Microsoft-Windows-Sysmon/Operational"
# # event_timestamp = "2017-06-25T17:13:00.453530200Z"  

# while True:
#     query_handle = win32evtlog.EvtQuery(
#             SYSMON_EVENT_LOG_PATH,
#             win32evtlog.EvtQueryForwardDirection,
#             SYSMON_XPATH_QUERY.format(
#                 event_log_path=SYSMON_EVENT_LOG_PATH,
#                 event_timestamp=event_timestamp),
#             None)
#     event = win32evtlog.EvtNext(query_handle, 1, 1, 0)
#     while event:
#         # converting the event to xml and then python object -> result in sysmon_record
#         ...
#         event_timestamp = sysmon_record.TimeCreated # the same parameter I query on
#         event = win32evtlog.EvtNext(...)

# import subprocess

# cmd = 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; StartTime=$EventStartDate} '\
#       '| Export-Clixml "sysmon_logs_last.xml"'
# list_files = subprocess.run(cmd)

import subprocess, sys

# p = subprocess.Popen(["powershell.exe", 'D:\\study\\диплом мага\\diplom\\helloworld.ps1'], stdout=sys.stdout)
# p.communicate()
# $EventStartDate = ((Get-Date).AddHours(-2))
# Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; StartTime=$EventStartDate}
# p = subprocess.Popen(["powershell.exe", 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; StartTime=((Get-Date).AddHours(-2))}'])
def get_new_logs():
    new_logs = subprocess.call('helloworld.ps1"') # тут команда из командной строки возвращает xml за последние 2 часа
    


