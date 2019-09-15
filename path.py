#!/usr/bin/env python
# _*_ coding: utf-8 _*
"""
Using CERT R4.2. One user one month pas is used to generate PAS. 
Using 2010.01-04 login data train, and the 2010.05 data is injected malicious lateral movement events.
generate PAS for each user.
"""
import sys
import time
import numpy as np
import json
import networkx as nx


def dict_to_nx(dict):
    """
    
    :param dict: {node:[adj1, ...]}
    :return: 
    """
    G = nx.DiGraph()
    for v, adj in dict.items():
        for j in adj:
            G.add_edge(v, j)
    return G


def load_json(file_name):
    return json.load(open(file_name, 'r'))


def store_json(contents, file_name):
    json.dump(contents, open(file_name, 'w'))


def sample_from_exp_distribution(Lambda):
    z = np.random.uniform(0, 1)
    return -np.log(1 - z) / Lambda


def chain_generation(whole_g, g, Lambda=0.0001, explore_rate=0.1, start_time=0, end_time=7*24*3600):
    whole_g.remove_edges_from(whole_g.selfloop_edges())
    g.remove_edges_from(g.selfloop_edges())

    start_nodes = [n for n, i in g.in_degree(g) if i == 0]  # the nodes that indegree == 0
    start_node = start_nodes[np.random.randint(len(start_nodes))]    # random select a node

    # chain init
    t = start_time   # start time
    visited = {n: False for n in whole_g.nodes()}
    V_c = [start_node]    # compromised nodes
    E_c = []    # compromised edges
    visited[start_node] = True
    Epsilon = list(g.edges(start_node))    # available auth events(edges with attributes)

    count = 0

    while len(Epsilon) >= 1 and t <= end_time:
        tau = sample_from_exp_distribution(Lambda)
        t = t + tau
        count += 1
        #print("malicious event happen at time: %d, which is step: %d" % (t, count))

        if np.random.uniform(0, 1) > explore_rate:  #exploit
            # select a computer to compromise
            red_event = Epsilon[np.random.randint(len(Epsilon))]
            compromised = red_event[1]
            #print("EXPLOIT: login event is %s -- %s" % (red_event[0], red_event[1]))
        else:   # explore
            while True:
                compromised = list(whole_g.nodes)[np.random.randint(len(whole_g))]
                if compromised not in g:
                    break
            red_event = (V_c[-1], compromised)
            #print("EXPLORE: login event is %s -- %s" % (red_event[0], red_event[1]))

        visited[compromised] = True
        V_c.append(compromised)
        E_c.append(red_event)

        # remove used edges
        Epsilon = [(s, d) for s, d in Epsilon if ((d != compromised) and (not visited[d]))]

        # add new edges that can be exploited
        susp_edges = [(compromised, susp) for susp in list(whole_g.neighbors(compromised)) if not visited[susp]]

        Epsilon = Epsilon + susp_edges

    return V_c, E_c


def inject_malicious_events(u_events, original_u_graph):
    """

    :param u_events: dict, key=red user, value=[(malicious events)]
    :param original_u_graph: 
    :return: 
    """
    for u, events in u_events.items():
        pas = original_u_graph[u]
        for (i, j) in events:
            if i not in pas:
                pas[i] = [j]
            if j not in pas[i]:
                pas[i].append(j)

if __name__ == "__main__":
    lbd = float(sys.argv[1])
    er = float(sys.argv[2])

    start = time.time()
    # load whole graph
    whole_graph_dict = load_json("/home/wei/myGit/paper/bipartiteEMB_my/ICICS/path_generation/whole_graph_inferred_by_pas.json")
    whole_g = dict_to_nx(whole_graph_dict)

    # load prepared u_graph
    u_graph_dict = load_json("/home/wei/myGit/paper/bipartiteEMB_my/ICICS/path_generation/u_graph.json_for_lmgeneration")

    ###########################################
    ############################################

    malicious_u_events = dict()
    for i in range(20):     # set the number of red users
        # random select a user #####
        red_u = ""
        while True:
            users = list(u_graph_dict.keys())
            red_u = users[np.random.randint(len(users))]
            if len(u_graph_dict[red_u]) >= 10 and red_u not in malicious_u_events:
                break
        #print("the red user: %s is chosen" %red_u)
        # get PAS
        red_pas = dict_to_nx(u_graph_dict[red_u])

        # Malicious Lateral Movement Trace Generation
        v_c, e_c = chain_generation(whole_g=whole_g, g=red_pas, Lambda=lbd, explore_rate=er)
        #print(e_c)
        malicious_u_events[red_u] = e_c

    # inject malicious lm events into u_graph_dict ###############
    inject_malicious_events(malicious_u_events, u_graph_dict)

    # dump the result
    store_json(u_graph_dict, "/home/wei/myGit/paper/bipartiteEMB_my/ICICS/path_generation/u_graph_with_LM.json")
    print("Lambda: %f, explore_rate: %f. The corresponding path: u_graph_with_LM.json has generated and saved. "
          "consuming time: %f" % (lbd, er, time.time() - start))
