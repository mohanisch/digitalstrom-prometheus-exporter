#!/usr/bin/env python3

import os
import json
import time
import urllib.request as urllib2
from urllib.parse import urlparse
from urllib.error import URLError, HTTPError
from prometheus_client import start_http_server
from prometheus_client.core import GaugeMetricFamily, REGISTRY
import argparse
import ssl

if not os.environ.get('PYTHONHTTPSVERIFY', '') and getattr(ssl, '_create_unverified_context', None):
    ssl._create_default_https_context = ssl._create_unverified_context


def valid_url(string):
    """Validate url input argument.
    Takes a string. Return valid url or raise URLError.
    """
    try:
        if not getattr(urlparse(string), "scheme") or \
                not getattr(urlparse(string), "netloc"):
            raise URLError("""Invalid URL: %s.
                        Don't forget including the scheme (usually http)
                        Example: https://dss.local:8080""" % string)

        return string
    except AttributeError:
        raise URLError("""Invalid URL: %s.
                       Don't forget including the scheme (usually http)
                       Example: https://dss.local:8080""" % string)


def parse():
    parser = argparse.ArgumentParser(
        description='Export Prometheus metrics dSS')
    parser.add_argument(
        '--host', metavar='HOST',
        type=valid_url,
        help='address with port where dSS is available. Defaults to\
        https://dss.local:8080',
        default=os.environ.get("DSS_HOST", "https://dss.local:8080")
    )
    parser.add_argument(
        "--logintoken", "-l", help="logintoken",
        default=os.environ.get("DSS_LOGINTOKEN", "")
    )
    return parser.parse_args()


class DssCollector(object):
    def __init__(self, target, logintoken):
        self._target = target.rstrip("/")
        self._auth = logintoken
        self._appartment = {}
        self._sessiontoken = self.get_session_token()
        self._circuits = self.collect_circuits()
        self._devices = self.collect_devices()
        self._data = {}

    def get_session_token(self):
        sessiontoken_request = urllib2.Request(
            "{0}/json/system/loginApplication?loginToken={1}".format(
                self._target, self._auth))
        return json.loads(urllib2.urlopen(sessiontoken_request).read())['result']['token']

    def collect_circuits(self):
        circuits = []
        circuits_request = urllib2.Request(
            "{0}/json/apartment/getCircuits".format(
                self._target))
        circuits_request.add_header("Cookie", "token=%s" % self._sessiontoken)
        print("Collecting circuits...")
        circuits_list = json.loads(urllib2.urlopen(circuits_request).read())['result']['circuits']

        for circuit_data in circuits_list:
            if circuit_data['dsid']:
                circuit_details = {'name': circuit_data['name'], 'dsid': circuit_data['dsid']}
                circuits.append(circuit_details)
        print("Collecting devices... Done. Found {0} circuits.".format(len(circuits)))

        return circuits

    def collect_devices(self):
        devices_request = urllib2.Request(
            "{0}/json/apartment/getDevices".format(
                self._target))
        devices_request.add_header("Cookie", "token=%s" % self._sessiontoken)
        print("Collecting devices...")
        devices = json.loads(urllib2.urlopen(devices_request).read())['result']
        print("Collecting devices... Done. Found {0} devices.".format(len(devices)))

        return devices

    def collect_circuit_details(self, dsid, type):
        details_request = urllib2.Request(
            "{0}/json/circuit/{2}?id={1}".format(self._target, dsid, type))
        details_request.add_header("Cookie", "token=%s" % self._sessiontoken)
        return json.loads(urllib2.urlopen(details_request).read())['result']

    def collect(self):
        try:
            self._request_data()
        except HTTPError as err:
            if err.code == 401:
                fatal('Authentication failure, attempting to restart')
        except URLError as err:
            fatal(err)

        i = self._appartment['result']
        yield GaugeMetricFamily(
            'dss_appartment_consumption',
            'Available Processors', value=i['consumption'])

        dcc = GaugeMetricFamily(
            'dss_circuit_consumption',
            'Current power consumption [W]',
            labels=["circuit", "fstype"])
        dcm = GaugeMetricFamily(
            'dss_circuit_metervalue',
            'Current measurent of the power consumption [Ws]',
            labels=["circuit", "fstype"])

        for circuit in self._circuits:
            circuit_name = self._mount_point(circuit['name'])
            circuit_consumption = (self.collect_circuit_details(circuit['dsid'], 'getConsumption'))
            circuit_energymetervalue = (self.collect_circuit_details(circuit['dsid'], 'getEnergyMeterValue'))

            dcc.add_metric(
                [circuit_name, "fsname", circuit['name']], circuit_consumption['consumption'])

            dcm.add_metric(
                [circuit_name, "fsname", circuit['name']], circuit_energymetervalue['meterValue'])
        yield dcc
        yield dcm

        ddp = GaugeMetricFamily(
            'dss_device_is_present',
            'Current state of device',
            labels=["device", "fstype"])
        for device in self._devices:
            device_name = self._mount_point(device['name'])

            ddp.add_metric(
                [device_name, "fsname", device_name], device['isPresent'])
        yield ddp

        ### disabled as the response takes very long
        ### TODO: This collection should only run sometimes a day, not all the time
        # dtq = GaugeMetricFamily(
        #     'dss_device_transmission_quality',
        #     'The actual transmission quality (upstream: 0 to 62, 62 meaning best quality, downstream: 0 to 6,'
        #     '0 meaning best quality)',
        #     labels=["device", "fstype"])
        #
        # for device in self._devices:
        #     device_name = self._mount_point(device['name'])
        #     device_quality_request = urllib2.Request(
        #         "{0}/json/device/getTransmissionQuality?dsuid={1}".format(
        #             self._target, device['dSUID']))
        #     device_quality_request.add_header("Cookie", "token=%s" % self._sessiontoken)
        #     device_quality = json.loads(urllib2.urlopen(device_quality_request).read())['result']
        #     dtq.add_metric(
        #         [device_name, "upstream", device_name], device_quality['upstream'])
        #     dtq.add_metric(
        #         [device_name, "downstream", device_name], device_quality['downstream'])
        # yield dtq

    def _mount_point(self, description):
        return description.split('(')[0].strip()

    def _request_data(self):
        appartment_request = urllib2.Request(
            "{0}/json/apartment/getConsumption".format(
                self._target))
        appartment_request.add_header("Cookie", "token=%s" % self._sessiontoken)
        self._appartment = json.loads(urllib2.urlopen(appartment_request).read())


def fatal(msg):
    print(msg)
    os._exit(1)  # hard exit without throwing exception


if __name__ == "__main__":
    print("initialising...")
    args = parse()
    REGISTRY.register(DssCollector(args.host, args.logintoken))
    start_http_server(9184)
    print("starting...")

    while True:
        time.sleep(1)