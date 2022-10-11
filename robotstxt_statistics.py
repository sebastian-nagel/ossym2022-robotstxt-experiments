import re

from collections import defaultdict, OrderedDict
from urllib.parse import urlparse

import ujson as json

from pyspark.sql.types import StructType, StructField, StringType, LongType

from sparkcc import CCSparkJob


class RobotstxtStatsJob(CCSparkJob):
    """ Collect robots.txt statistics from WARC response records
        (robots.txt subset)"""

    name = "RobotstxtStats"

    plain_text_mime_types = {'text/x-robots', 'text/plain', 'message/rfc822', 'text/text', 'text/txt',
                             'text', 'plain/text', 'text/pain', 'text/plan'}

    content_html_pattern = re.compile(b'^(?:<html|<!DOCTYPE html)\\b', re.IGNORECASE|re.ASCII)
    robotstxt_commentline_pattern = re.compile(b'^\\s*#')
    robotstxt_emptyline_pattern = re.compile(b'^\\s*$')
    robotstxt_known_directive_pattern = re.compile(b'^\\s*(user-agent|disallow|allow|crawl-delay|sitemap|clean-param|host|noindex)\\s*:\\s*([^\r#]*)',
                                                   re.IGNORECASE|re.ASCII)
    robotstxt_unknown_directive_pattern = re.compile(b'^\\s*([a-z_]+(?:-[a-z_]+)*)\\s*:',
                                                     re.IGNORECASE|re.ASCII)
    white_space_pattern = re.compile('\\s+')

    output_schema = StructType([
        StructField("key", StructType([
            StructField("directive", StringType(), True),
            StructField("value", StringType(), True)]), True),
        StructField("cnt", LongType(), True)
    ])

    def add_arguments(self, parser):
        parser.add_argument("--extract_rulesets", action='store_true',
                            help="Extract rulesets per host as JSON (note: this adds a lot of output data)")

    def init_accumulators(self, session):
        super(RobotstxtStatsJob, self).init_accumulators(session)

        sc = session.sparkContext
        self.records_not_response = sc.accumulator(0)
        self.records_not_http_200 = sc.accumulator(0)
        self.records_not_plain_text = sc.accumulator(0)
        self.robots_lines = sc.accumulator(0)
        self.robots_directives = sc.accumulator(0)

    def log_accumulators(self, session):
        super(RobotstxtStatsJob, self).log_accumulators(session)

        self.log_accumulator(session, self.records_not_response,
                             'records not WARC response = {}')
        self.log_accumulator(session, self.records_not_http_200,
                             'records not HTTP 200 ok = {}')
        self.log_accumulator(session, self.records_not_plain_text,
                             'records not plain text = {}')
        self.log_accumulator(session, self.robots_lines,
                             'robots.txt lines processed = {}')
        self.log_accumulator(session, self.robots_directives,
                             'robots.txt directives found = {}')

    def process_record(self, record):
        if not record.rec_type == 'response':
            # warcinfo, request, metadata records
            self.records_not_response.add(1)
            return

        if record.http_headers.get_statuscode() != '200':
            self.records_not_http_200.add(1)
            return

        mime_detected = record.rec_headers.get_header('WARC-Identified-Payload-Type')
        if mime_detected:
            if not mime_detected in RobotstxtStatsJob.plain_text_mime_types:
                self.records_not_plain_text.add(1)
                return
        else:
            mime_type = record.http_headers.get_header('Content-Type')
            if not mime_type:
                return # todo
            mime_type = mime_type.split(';')[0].strip().lower()
            if mime_type in RobotstxtStatsJob.plain_text_mime_types:
                pass # ok
            else:
                self.get_logger().debug("Skipped HTTP Content-Type: %s", mime_type)
                self.records_not_plain_text.add(1)
                return

        url = record.rec_headers.get_header('WARC-Target-URI')
        host_name = urlparse(url).hostname

        stream = record.content_stream()       
        line = stream.readline()
        # TODO: should consider also '\r' as line break

        if line:
            if line.startswith(b'\xef\xbb\xbf'):
                yield ('(bom stripped)', None), 1
                line = line[3:]
            if RobotstxtStatsJob.content_html_pattern.match(line):
                # skip over HTML content not recognized as such by HTTP header
                self.get_logger().debug("Skipped HTML (first content line): %s", line)
                self.records_not_plain_text.add(1)
                return                

        rules_by_agent = None
        active_agents = None
        inblock = False
        if self.args.extract_rulesets:
            rules_by_agent = defaultdict(list)
            active_agents = set()

        while line:

            self.robots_lines.add(1)          

            m = RobotstxtStatsJob.robotstxt_commentline_pattern.match(line)
            if m:
                yield ('(comment line)', None), 1
                line = stream.readline()
                continue

            m = RobotstxtStatsJob.robotstxt_emptyline_pattern.match(line)
            if m:
                yield ('(empty line)', None), 1
                line = stream.readline()
                continue

            m = RobotstxtStatsJob.robotstxt_known_directive_pattern.match(line)
            if m:
                self.robots_directives.add(1)
                directive = m.group(1).lower().decode('utf-8', errors='replace')
                value = m.group(2).strip().decode('utf-8', errors='replace')
                value = RobotstxtStatsJob.white_space_pattern.sub(' ', value)
                # note: comments are excluded from matched value
                yield (directive, value), 1
                line = stream.readline()
                if self.args.extract_rulesets:
                    if directive == 'user-agent':
                        if inblock:
                            active_agents = set()
                        active_agents.add(value)
                    elif directive in {'allow', 'disallow'}:
                        inblock = True
                        for agent in active_agents:
                            rules_by_agent[agent].append((directive, value))
                continue

            m = RobotstxtStatsJob.robotstxt_unknown_directive_pattern.match(line)
            if m:
                directive = m.group(1).lower().decode('utf-8', errors='replace')
                yield ('(unknown directive)', directive), 1
                line = stream.readline()
                continue

            self.get_logger().info("Unknown line: %s", line)
            yield ('(unknown line)', None), 1

            line = stream.readline()

        if self.args.extract_rulesets:
            d = OrderedDict()
            for agent in sorted(rules_by_agent):
                d[agent] = defaultdict(list)
                for (directive, value) in sorted(rules_by_agent[agent]):
                    d[agent][directive].append(value)
            ruleset = json.dumps({host_name: d})
            yield ('(ruleset)', ruleset), 1


if __name__ == "__main__":
    job = RobotstxtStatsJob()
    job.run()
