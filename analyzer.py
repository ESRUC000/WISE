from fil_scanner import scan

from perf_check import analyze as performance_analyze
from sec_check import analyze as security_analyze
from channel_check import analyze as channel_analyze
from recommendations import analyze as recommendation_analyze
from channel_recommender import recommend_channel


def analyze():

    # Scan nearby networks
    networks = scan()

    # Analyze the overall wireless environment
    environment = recommend_channel(networks)

    analyzed_networks = []

    # Analyze each network
    for network in networks:

        network = performance_analyze(network)
        network = security_analyze(network)
        network = channel_analyze(network)
        network = recommendation_analyze(
            network,
            environment,
            networks
        )

        analyzed_networks.append(network)

    return analyzed_networks, environment