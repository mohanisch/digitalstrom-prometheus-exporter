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
        "--bearertoken", "-l", help="bearertoken",
        default=os.environ.get("DSS_BEARERTOKEN", "")
    )
    return parser.parse_args()


class DssCollector(object):
    def __init__(self, target, bearertoken):
        self._target = target.rstrip("/")
        self._base_uri = "/api/v1"
        self._auth = bearertoken

        self._appartment = {}
        self._controllers = {}
        self._meterings = {}
        self._zones = {}
        self._devices = {}
        self._devices_status = {}

    def _zone_attributes_by_id(self, zoneid):
        _attr = {}
        if zoneid in ("0", "65534"):
            _attr = {zoneid: {'name': "unknown"}}
        else:
            _attr = {zone['id']: zone['attributes'] for zone in self._zones}
        return _attr[str(zoneid)]

    def request(self, uri=""):
        request = urllib2.Request(
            "{0}/{1}/apartment/{2}".format(
                self._target, self._base_uri, uri))
        request.add_header("Authorization", "Bearer %s" % self._auth)
        request_data = json.loads(urllib2.urlopen(request).read())['data']

        return request_data

    def collect(self):
        metering_value_by_meter_id = {}
        controller_name_by_id = {}
        device_attributes_by_id = {}

        try:
            self._request_data()
            meterings_values = self.request("installation/meterings/values")["values"]
            metering_value_by_meter_id = {circuits_value['id']: circuits_value['attributes']['value'] for circuits_value
                                          in meterings_values}
            controller_name_by_id = {controller['id']: controller['attributes']['name'] for controller in
                                     self._controllers}
            device_attributes_by_id = {device['id']: device['attributes'] for device in self._devices}
        except HTTPError as err:
            if err.code == 401:
                fatal('Authentication failure, attempting to restart')
        except URLError as err:
            fatal(err)

        i = self._appartment
        dss_appartment_temprature = i['attributes']['measurements']['temperature'] if "measurements" in i[
            'attributes'] else 0
        yield GaugeMetricFamily(
            'dss_appartment_temprature',
            'Current temprature [°]', value=dss_appartment_temprature)

        dcc = GaugeMetricFamily(
            'dss_controller',
            'Available controllers in dS',
            labels=["id", "name"])

        for controller in self._controllers:
            if 'attributes' in controller:
                dcc.add_metric(
                    [controller['id'], controller['attributes']['name']], 1)
        yield dcc

        dmc = GaugeMetricFamily(
            'dss_metering_consumption',
            'Current power consumption per meter [W]',
            labels=["name", "hwName"])
        dmm = GaugeMetricFamily(
            'dss_metering_metervalue',
            'Current measurent of the power consumption [Ws]',
            labels=["name", "hwName"])

        for metering in self._meterings:
            if 'attributes' in metering:
                if 'id' in metering['attributes']['origin']:
                    metering_details = {
                        'id': metering['id'],
                        'dsid': metering['attributes']['origin']['id'],
                        'unit': metering['attributes']['unit'],
                        'meterType': metering['attributes']['technicalName'].split()[0],
                        'meterValueType': metering['attributes']['technicalName'].split()[1]
                    }
                    meter_value = (metering_value_by_meter_id[metering_details['id']])
                    if metering_details['meterValueType'] == 'power':
                        dmc.add_metric(
                            [controller_name_by_id[metering_details['dsid']],
                             metering_details['meterType'],
                             metering_details['meterValueType']], meter_value)
                    if metering_details['meterValueType'] == 'energy':
                        dmm.add_metric(
                            [controller_name_by_id[metering_details['dsid']],
                             metering_details['meterType'],
                             metering_details['meterValueType']], meter_value)
        yield dmc
        yield dmm

        ddp = GaugeMetricFamily(
            'dss_device_is_present',
            'Current state of device',
            labels=["device", "zone"])

        for device in self._devices:
            d = {
                "id": device['id'],
                "name": device['attributes']['name'],
                "present": device['attributes']['present'],
                "zone": self._zone_attributes_by_id(device['attributes']['zone'])['name']
            }
            ddp.add_metric(
                [d['name'], d['zone'], d['name']], d['present'])

        yield ddp

        dss_device_value = GaugeMetricFamily(
            'dss_device_value',
            'Current function value of device in percent',
            labels=["device", "zone", "type", "value"])
        dss_device_state = GaugeMetricFamily(
            'dss_device_state',
            'Current function status of device. 1 = ok, 2 = moving/dimming',
            labels=["device", "zone", "type", "status"])

        for device in self._devices_status:
            if "outputs" in device['attributes']['functionBlocks'][0]:
                outputs = device['attributes']['functionBlocks'][0]['outputs'][0]

                targetvalue = outputs['targetValue'] if "targetValue" in outputs else ""
                value = outputs['value'] if "value" in outputs else targetvalue

                d = {
                    "id": device['attributes']['functionBlocks'][0]['id'],
                    "type": device['attributes']['functionBlocks'][0]['outputs'][0]['id'],
                    "value": value,
                    "status": device['attributes']['functionBlocks'][0]['outputs'][0]['status'],
                }
                device_name = device_attributes_by_id[d['id']]['name']
                device_zone = self._zone_attributes_by_id(device_attributes_by_id[d['id']]['zone'])['name']

                state_float = 0
                if d['status'] == "ok":
                    state_float = 1
                if d['status'] == "moving":
                    state_float = 2

                dss_device_value.add_metric(
                    [device_name, device_zone, d['type']], round(d['value'], 0))
                dss_device_state.add_metric(
                    [device_name, device_zone, d['type']], state_float)

        yield dss_device_value
        yield dss_device_state

        dss_zone_measurements = GaugeMetricFamily(
            'dss_zone_measurements',
            'Current measurements value of zone - temperature in degree, humidity in percent, '
            'brightness in lux, motion in bool ',
            labels=["zone", "type", "value"])

        for zones_measurement in self._zones_measurements:
            if zones_measurement['id'] == "65534":
                continue
            else:
                if 'measurements' in zones_measurement['attributes']:
                    zone_name = self._zone_attributes_by_id(zones_measurement['id'])['name']

                    for measurement, value in zones_measurement['attributes']['measurements'].items():
                        dss_zone_measurements.add_metric(
                            [zone_name, measurement], round(value, 0))

        yield dss_zone_measurements

    def _request_data(self):
        self._appartment = self.request("/status")
        self._controllers = self.request("/controllers")['controllers']
        self._meterings = self.request("meterings")['meterings']
        self._zones = self.request("zones")['zones']
        self._zones_measurements = self.request("zones/status")
        self._devices = self.request("dsDevices")
        self._devices_status = self.request("dsDevices/status")


def fatal(msg):
    print(msg)
    os._exit(1)  # hard exit without throwing exception


if __name__ == "__main__":
    print("initialising...")
    args = parse()
    REGISTRY.register(DssCollector(args.host, args.bearertoken))
    start_http_server(9184)
    print("starting...")

    while True:
        time.sleep(1)
