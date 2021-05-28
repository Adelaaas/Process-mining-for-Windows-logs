import pm4py
import pandas as pd
from pm4py.algo.discovery.alpha import algorithm as alpha_miner
from pm4py.algo.discovery.inductive import algorithm as inductive_miner
from pm4py.algo.discovery.heuristics import algorithm as heuristics_miner
from pm4py.algo.discovery.dfg import algorithm as dfg_discovery
from pm4py.objects.conversion.log import converter as log_converter
from pm4py.algo.discovery.alpha import algorithm as alpha_miner
from pm4py.visualization.petrinet import visualizer as pn_visualizer
from pm4py.visualization.process_tree import visualizer as pt_visualizer
from pm4py.visualization.heuristics_net import visualizer as hn_visualizer
from pm4py.visualization.dfg import visualizer as dfg_visualization
from pm4py.algo.evaluation.replay_fitness import algorithm as replay_fitness_evaluator
from pm4py.algo.evaluation.precision import algorithm as precision_evaluator
from pm4py.algo.evaluation.generalization import algorithm as generalization_evaluator

def compare_alg(df):
    # конвертация DataFrame в логи
    log = log_converter.apply(df, variant=log_converter.Variants.TO_EVENT_LOG)
    
    # применение Alpha алгоритма для обнаружения процессов
    net, initial_marking, final_marking = alpha_miner.apply(log)
    gviz = pn_visualizer.apply(net, initial_marking, final_marking)
    pn_visualizer.view(gviz)
    # получение оценок для Alpha алгоритма
    gen = generalization_evaluator.apply(log, net, initial_marking, final_marking)
    prec = precision_evaluator.apply(log, net, initial_marking, final_marking, variant=precision_evaluator.Variants.ALIGN_ETCONFORMANCE)
    # prec = precision_evaluator.apply(log, net, im, fm, variant=precision_evaluator.Variants.ETCONFORMANCE_TOKEN)
    # fitness = replay_fitness_evaluator.apply(log, net, im, fm, variant=replay_fitness_evaluator.Variants.ALIGNMENT_BASED)
    fitness = replay_fitness_evaluator.apply(log, net, initial_marking, final_marking, variant=replay_fitness_evaluator.Variants.ALIGNMENT_BASED)
    alpha_metrics = [gen, prec, fitness]

    # Построение DFG Графа
    dfg = dfg_discovery.apply(log)
    gviz = dfg_visualization.apply(dfg, log=log, variant=dfg_visualization.Variants.FREQUENCY)
    dfg_visualization.view(gviz)

    # применение индуктивного метода обнаружения процессов
    net, initial_marking, final_marking = inductive_miner.apply(log)
    tree = inductive_miner.apply_tree(log)
    gviz = pt_visualizer.apply(tree)
    pt_visualizer.view(gviz)
    # получение оценок для индуктивного метода
    gen = generalization_evaluator.apply(log, net, initial_marking, final_marking)
    prec = precision_evaluator.apply(log, net, initial_marking, final_marking, variant=precision_evaluator.Variants.ALIGN_ETCONFORMANCE)
    # prec = precision_evaluator.apply(log, net, im, fm, variant=precision_evaluator.Variants.ETCONFORMANCE_TOKEN)
    # fitness = replay_fitness_evaluator.apply(log, net, im, fm, variant=replay_fitness_evaluator.Variants.ALIGNMENT_BASED)
    fitness = replay_fitness_evaluator.apply(log, net, initial_marking, final_marking, variant=replay_fitness_evaluator.Variants.ALIGNMENT_BASED)
    inductive_metrics = [gen, prec, fitness]

    # применение Эвристического метода обнаружения процессов
    heu_net = heuristics_miner.apply_heu(log, parameters={heuristics_miner.Variants.CLASSIC.value.Parameters.DEPENDENCY_THRESH: 0.99})
    gviz = hn_visualizer.apply(heu_net)
    hn_visualizer.view(gviz)
    # получение оценок для Эвристического метода
    gen = generalization_evaluator.apply(log, net, initial_marking, final_marking)
    prec = precision_evaluator.apply(log, net, initial_marking, final_marking, variant=precision_evaluator.Variants.ALIGN_ETCONFORMANCE)
    # prec = precision_evaluator.apply(log, net, im, fm, variant=precision_evaluator.Variants.ETCONFORMANCE_TOKEN)
    # fitness = replay_fitness_evaluator.apply(log, net, im, fm, variant=replay_fitness_evaluator.Variants.ALIGNMENT_BASED)
    fitness = replay_fitness_evaluator.apply(log, net, initial_marking, final_marking, variant=replay_fitness_evaluator.Variants.ALIGNMENT_BASED)
    heuristics_metrics = [gen, prec, fitness]

    compare_algorithms = pd.DataFrame(index=['Fitness', 'Precision', 'Generalization'])
    compare_algorithms['Alpha'] = alpha_metrics
    compare_algorithms['Inductive'] = inductive_metrics
    compare_algorithms['Heuristics'] = heuristics_metrics
    
    # поиск наилучшего алгоритма
    best = compare_algorithms.mean(axis=0).idxmax()
    return best

# функция преобразования журнала событий
# в формат необходимый для применения Process mining
def csv_to_logs(df):
    data_frame = pd.DataFrame()
    df['UtcTime'] = pd.to_datetime(df['UtcTime'])
    data_frame['case:concept:name'] = df['Case id']
    data_frame['concept:name'] = df['Image']
    data_frame['time:timestamp'] = df['UtcTime']
    data_frame = data_frame.sort_values('time:timestamp')
    return data_frame

# get_paths, get_all_paths - иерархи событий
def get_paths(df, find):
    sequences = [find]
    first = find
    for index, row in df.iterrows():
            sequences.append(row['ParentProcessId:'] + '|' + row['ProcessId'])
            for c in sequences.copy():
                if c.split('|')[0] == row['ProcessId']:
                    sequences.append(row['ParentProcessId:'] + '|' + c)

    # удалим из последовательности другие процессы, которые не начинаются с переданного id
    sequences2 = []
    for seq in sequences:
        tmp = seq.split('|')
        if tmp[len(tmp)-1] == first:
            sequences2.append(seq)

    # удалим из цепочек событий, те которые входя в более крупные
    sequences2 = max(sequences2, key=len)
    return sequences2

def get_all_paths(df):
    df['ParentProcessId:'] = df['ParentProcessId:'].astype(str)
    df['ProcessId'] = df['ProcessId'].astype(str)
    chains = []
    for index, row in df.iterrows():
        chains.append(get_paths(df, row['ProcessId']))
    return chains

if __name__ == "__main__":
    df = pd.read_csv("process_example.csv")
    # print("ProcessId:", df['ProcessId'].value_counts())
    # chains = get_all_paths(df)
    # print(chains)
    df = csv_to_logs(df)
    print(df)
    compare_alg(df)
