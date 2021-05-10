import pm4py
from pm4py.objects.conversion.log import converter as log_converter
from pm4py.algo.discovery.dfg import algorithm as dfg_algorithm
import pandas as pd
from pm4py.algo.discovery.alpha import algorithm as alpha_miner
import pm4py

# Функция для преобразования полей CSV файла в формат,
# необходимый для Process mining
# def csv_to_logs(df):
#     cols = ['case:concept:name','concept:name','time:timestamp']
#     df.columns = cols
#     app['time:timestamp'] = pd.to_datetime(app['time:timestamp'])
#     log = log_converter.apply(app, variant=log_converter.Variants.TO_EVENT_LOG)
#     process_model, initial_marking, final_marking = pm4py.discover_petri_net_inductive(log)
#     pm4py.view_petri_net(process_model, initial_marking, final_marking, format="svg")

def csv_to_logs(df):
    data_frame = pd.DataFrame()
    df['UtcTime'] = pd.to_datetime(df['UtcTime'])
    data_frame['case:concept:name'] = df['ProcessId']
    data_frame['concept:name'] = df['Image']
    data_frame['time:timestamp'] = df['UtcTime']
    return data_frame


df = pd.read_csv("sysmon_logs_prepared2.csv")
print("ProcessId:", df['ProcessId'].value_counts())
df2 = csv_to_logs(df)
print(df2.head())


log = log_converter.apply(df2, variant=log_converter.Variants.TO_EVENT_LOG)
# # print(log)

# process_model, initial_marking, final_marking = pm4py.discover_petri_net_inductive(log)
# pm4py.view_petri_net(process_model, initial_marking, final_marking, format="svg")
from pm4py.algo.discovery.inductive import algorithm as inductive_miner
from pm4py.visualization.process_tree import visualizer as pt_visualizer

net, initial_marking, final_marking = inductive_miner.apply(log)

tree = inductive_miner.apply_tree(log)

gviz = pt_visualizer.apply(tree)
pt_visualizer.view(gviz)