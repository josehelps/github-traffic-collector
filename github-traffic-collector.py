import argparse
import sys
from github import Github
from modules.CustomConfigParser import CustomConfigParser
from modules import logger
from pathlib import Path
from tqdm import tqdm
import json
from datetime import datetime
# import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VERSION = 1


def send_to_splunk(traffic_stats, config, log):
    full_url = config['splunk_host']+'/services/collector/raw'
    http = urllib3.PoolManager(cert_reqs='CERT_NONE', assert_hostname=False)
    urllib3.disable_warnings()
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Splunk ' + config['splunk_hec_token']
    }
    for stat in traffic_stats:
        data = json.dumps(stat).encode('utf8')
        r = http.request('POST', full_url, body=data, headers=headers)
        if r.status == 200:
            log.info(
                "successfully posted event: "
                "{0} to splunk: {1} via HEC".format(
                    stat, full_url)
            )
        else:
            log.error(
                "posting event {0} to splunk: {1} via HEC "
                "with return code: {2} and data: {3}".format(
                    stat, full_url, r.status, r.data)
            )


def write_traffic(traffic_stats, output_path, log):
    try:
        with open(output_path, 'a') as outfile:
            json.dump(traffic_stats, outfile)
    except Exception as e:
        log.error("writing result file: {0}".format(str(e)))


def collect_traffic_stats(github_token, tracking_repos, log):
    traffic_stats = []
    g = Github(login_or_token=github_token, per_page=100)
    log.info(
        "processing traffic stats for {0} out of {1} "
        "repos available to your github token.".format(
            len(tracking_repos), g.get_user().get_repos().totalCount)
        )
    for repo in tqdm(
            g.get_user().get_repos(), total=g.get_user().get_repos().totalCount
            ):
        if repo.name in tracking_repos:
            traffic = repo.get_views_traffic()
            paths = repo.get_top_paths()
            clones = repo.get_clones_traffic()
            referrers = repo.get_top_referrers()
            now = datetime.now()
            
            for view in traffic['views']:
                stat = dict()
                stat['type'] = "view"
                stat['repo'] = repo.name
                stat['count'] = view.count
                stat['uniques'] = view.uniques
                stat['timestamp'] = str(view.timestamp)
                traffic_stats.append(stat)
            for path in paths:
                stat = dict()
                stat['type'] = "path"
                stat['repo'] = repo.name
                stat['count'] = path.count
                stat['uniques'] = path.uniques
                stat['path'] = path.path
                stat['timestamp'] = str(now.strftime("%Y-%m-%dT%H:%M:%S"))
                traffic_stats.append(stat)
            for clone in clones['clones']:
                stat = dict()
                stat['type'] = "clone"
                stat['repo'] = repo.name
                stat['count'] = clone.count
                stat['uniques'] = clone.uniques
                stat['timestamp'] = str(clone.timestamp)
                traffic_stats.append(stat)
            for referrer in referrers:
                stat = dict()
                stat['type'] = "referrer"
                stat['repo'] = repo.name
                stat['count'] = referrer.count
                stat['uniques'] = referrer.uniques
                stat['referrer'] = referrer.referrer
                stat['timestamp'] = str(now.strftime("%Y-%m-%dT%H:%M:%S"))
                traffic_stats.append(stat)

    return traffic_stats


if __name__ == "__main__":
    # Setup arguments
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c", "--config", required=False,
        default="github-traffic-collector.conf",
        help="config file path"
    )
    parser.add_argument(
        "-v", "--version", default=False,
        action="store_true", required=False,
        help="shows current github-traffic-collector version"
    )

    # parse them
    args = parser.parse_args()
    ARG_VERSION = args.version
    config = args.config

    # needs config parser here
    tool_config = Path(config)
    if tool_config.is_file():
        print(
            "github-traffic-collector is using config at "
            "path {0}".format(tool_config)
        )
        configpath = str(tool_config)
    else:
        print(
            "ERROR: github-traffic-collector failed to find "
            "a config file at {0}..exiting".format(tool_config))
        sys.exit(1)

    # Parse config
    parser = CustomConfigParser()
    config = parser.load_conf(configpath)

    log = logger.setup_logging(config['log_path'], config['log_level'])
    log.info("INIT - github-traffic-collector v" + str(VERSION))

    if ARG_VERSION:
        log.info("version: {0}".format(VERSION))
        sys.exit(0)

    github_token = config['github_token']

    if github_token == "TOKENHERE":
        print(
            "ERROR: github-traffic-collector failed to find "
            "a github_token in the config file at {0}..exiting".format(
                tool_config)
            )
        sys.exit(1)

    # collect github traffic stats
    if config['github_repos'] != '':
        traffic_stats = collect_traffic_stats(
            github_token, config['github_repos'].replace(
                " ", "").split(","), log
        )
    else:
        print(
            "ERROR: github-traffic-collector failed to find "
            "a github_repository to grab stats from, "
            "please see the config file at {0}..exiting".format(
                tool_config)
        )
        sys.exit(1)

    # write stats to disk
    write_traffic(traffic_stats, config['output'], log)
    log.info("sucessfully wrote {0} traffic stats to: {1}".format(
        len(traffic_stats), config['output'])
    )

    if config['splunk_hec_token'] != '':
        send_to_splunk(traffic_stats, config, log)
    else:
        log.error(
            "splunk_hec_token is not set on config file {0}"
            .format(tool_config)
        )
        sys.exit(1)
