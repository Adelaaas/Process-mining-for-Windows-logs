import pandas as pd
from lxml import etree as et
import re

# функция, которая принимает на вход журналы событий ОС Windows,
# полученные с помощью Sysmon в формате XML
# и преобразует события в формат CSV
def xml_to_df(xml_file):
    
    root = et.parse(xml_file).getroot()

    MachineName = []
    Task = []
    EventID = []
    Level = []
    Message = []
    RecordId = []
    ProcessId = []
    ThreadId = []
    TimeCreated = []
    events = []

    for index, child in enumerate(root):
        event = []
        for child2 in child:
            if child2.tag == 'Props':
                for i in child2:
                    if i.tag == 'S' and i.attrib['N'] == 'MachineName':
                        MachineName.append(i.text)
                    if i.tag == 'I32' and i.attrib['N'] == 'Id':
                        # <I32 N="Id">5</I32>
                        # print(i.text)
                        EventID.append(i.text)
                    if i.tag == 'By' and i.attrib['N'] == 'Level':
                        # <By N="Level">4</By>
                        # print(i.text)
                        Level.append(i.text)
                    if i.tag == 'I32' and i.attrib['N'] == 'Task':
                        # <I32 N="Task">5</I32>
                        Task.append(i.text)
                    if i.tag == 'I64' and i.attrib['N'] == 'RecordId':
                        # <I64 N="RecordId">118014</I64>
                        RecordId.append(i.text)
                    if i.tag == 'I32' and i.attrib['N'] == 'ProcessId':
                        # <I32 N="ProcessId">5444</I32>
                        ProcessId.append(i.text)
                    if i.tag == 'I32' and i.attrib['N'] == 'ThreadId':
                        # <I32 N="ThreadId">7912</I32>
                        ThreadId.append(i.text)
                    if i.tag == 'DT' and i.attrib['N'] == 'TimeCreated':
                        # <DT N="TimeCreated">2021-04-01T22:23:18.6572502+03:00</DT>
                        TimeCreated.append(i.text)
                    if i.tag == 'Obj' and i.attrib['N'] == 'Properties':
                    # <Obj N="Properties" RefId="5"> - надо найти это поле и достать оттуда все данные
                        # obj = []
                        for j in i:
                            # дальше гам нужен только тэг <LST>
                            # obj.append
                            # print(j.tag)
                            if j.tag == 'LST':
                                for k in j:
                                    # тут много тэгов obj, надо взять только последний
                                    # print(k.tag)
                                    if k.tag == 'Obj':
                                        for n in k:
                                            # в каждом obj нам нужен props
                                            # <Props>
                                            #     <S N="Value">C:\Windows\System32\svchost.exe</S>
                                            # </Props>
                                            if n.tag == 'Props':
                                                for s in n:
                                                    if (s.tag == 'S' or s.tag == 'G') and s.attrib['N'] == 'Value':
                                                        # <S N="Value"> - тут он только отсюда текст берет и записывает в события
                                                        # print(s.text) 
                                                        event.append(s.text)
            if child2.tag == 'MS':
                for i in child2:    
                    if i.tag == 'S' and i.attrib['N'] == 'Message':
                        Message.append(i.text)
        
        events.append(event)

    df = pd.DataFrame({'EventID': EventID, 'Level':Level, 'Task':Task,
                    'RecordId': RecordId, 'ProcessId': ProcessId, 'ThreadId':ThreadId,
                    'TimeCreated': TimeCreated, 'MachineName':MachineName, 'Message':Message,
                    'events': pd.Series(events)})
    return df

# Функция, которая дополняет журналы событий
# необходимыми парметрами
def xml_to_df2(df):
    df['UtcTime'] = ''
    df['CommandLine'] = ''
    df['ProcessGuid'] = ''
    df['ParentProcessGuid'] = ''
    df['ProcessId'] = ''
    df['ParentProcessId'] = ''
    df['Image'] = ''
    df['ParentImage'] = ''
    df['User'] = ''

    for index, row in df.iterrows():
        s1 = row['Message'].split('_')
        for i in s1:
            if re.findall(r'UtcTime:', i):
                df.loc[index,'UtcTime'] = re.split(r'UtcTime: ', i)[1]
            if re.findall(r'ProcessGuid: ', i):
                if re.split(r' ', i)[0] == 'ProcessGuid:':
                    df.loc[index,'ProcessGuid'] = re.split(r'ProcessGuid: ', i)[1]
                if re.split(r' ', i)[0] == 'ParentProcessGuid:':
                    df.loc[index,'ParentProcessGuid:'] = re.split(r'ParentProcessGuid: ', i)[1]
            if re.findall(r'ProcessId: ', i):
                if re.split(r' ', i)[0] == 'ProcessId:':
                    df.loc[index,'ProcessId'] = re.split(r'ProcessId: ', i)[1]
                if re.split(r' ', i)[0] == 'ParentProcessId:':
                    df.loc[index,'ParentProcessId:'] = re.split(r'ParentProcessId: ', i)[1]
            if re.findall(r'Image: ', i):
                if re.split(r' ', i)[0] == 'Image:':
                    df.loc[index,'Image'] = re.split(r'Image: ', i)[1]
                if re.split(r' ', i)[0] == 'ParentImage:':
                    df.loc[index,'ParentImage:'] = re.split(r'ParentImage: ', i)[1]
            if re.findall('CommandLine:', i):
                df.loc[index,'CommandLine'] = re.split(r'CommandLine: ', i)[1]
            if re.findall('User:', i):
                df.loc[index,'User'] = re.split(r'User: ', i)[1]
    return df


if __name__ == "__main__":
    # xml_file = "sysmon_logs_may.xml"
    # df = xml_to_df(xml_file)
    # df.to_csv("sysmon_logs_prepared.csv")
    df = pd.read_csv("sysmon_logs_prepared.csv")
    df = xml_to_df2(df)
    df.to_csv("sysmon_logs_prepared2.csv")
    print(df)
    print(df.columns)