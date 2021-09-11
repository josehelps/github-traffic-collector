import argparse
import sys
from github import Github, GithubException
from modules.CustomConfigParser import CustomConfigParser
from modules import logger
from pathlib import Path

VERSION = 1

def write_traffic(event, output_path):
    try:
        with open(output_path, 'a') as outfile:
            json.dump(leaks, outfile)
    except Exection as e:
        log.error("writing result file: {0}".format(str(e)))


def collect_traffic_stats(github_token, tracking_repos):
    g = Github(login_or_token=github_token, per_page=100)
    for repo in g.get_user().get_repos():
        if repo in tracking_repos:
            print(repo.name)
                #traffic = repo.get_views_traffic()
                #print(traffic)

if __name__ == "__main__":
    # Setup arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", required=False, default="github-traffic-collector.conf", help="config file path")
    parser.add_argument("-v", "--version", default=False, action="store_true", required=False, help="shows current github-traffic-collector version")

    # parse them
    args = parser.parse_args()
    ARG_VERSION = args.version
    config = args.config

    # needs config parser here
    tool_config = Path(config)
    if tool_config.is_file():
        print("github-traffic-collector is using config at path {0}".format(tool_config))
        configpath = str(tool_config)
    else:
        print("ERROR: github-traffic-collector failed to find a config file at {0} or {1}..exiting".format(tool_config))
        sys.exit(1)

    # Parse config
    parser = CustomConfigParser()
    config = parser.load_conf(configpath)

    log = logger.setup_logging(config['log_path'], config['log_level']
)
    log.info("INIT - github-traffic-collector v" + str(VERSION))

    if ARG_VERSION:
        log.info("version: {0}".format(VERSION))
        sys.exit(0)

    github_token = config['github_token']

    if github_token == "TOKENHERE":
        print("ERROR: github-traffic-collector failed to find a github_token in the config file at {0}..exiting".format(tool_config))
        sys.exit(1)

    if len(config['github_repos'].split(",")) > 0 :
        print(config['github_repos'].split(","))
        collect_traffic_stats(github_token, config['github_repos'].split(","))
    else:
        print("ERROR: github-traffic-collector failed to find a github_repository to grab stats from, please see the config file at {0}..exiting".format(tool_config))
        sys.exit(1)


