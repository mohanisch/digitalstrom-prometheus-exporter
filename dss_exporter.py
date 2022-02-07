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
        self._controllers = self.collect_controllers()
        self._zones = {}
        self._meterings = self.collect_meterings()
        self._circuits = self.circuits()
        self._output_devices = {}
        self._data = {}

    def request(self, uri=""):
        request = urllib2.Request(
            "{0}/{1}/apartment/{2}".format(
                self._target, self._base_uri, uri))
        request.add_header("Authorization", "Bearer %s" % self._auth)
        request_data = json.loads(urllib2.urlopen(request).read())['data']

        return request_data

    def collect_controllers(self):
        controllers = []
        controllers_list = self.request("controllers")['controllers']

        for controllers_data in controllers_list:
            if 'attributes' in controllers_data:
                controllers_details = {
                    'id': controllers_data['id'],
                    'name': controllers_data['attributes']['name']
                }
                controllers.append(controllers_details)

        return controllers

    def collect_meterings(self):
        meterings = []
        meterings_list = self.request("meterings")['meterings']

        for meterings_data in meterings_list:
            if 'attributes' in meterings_data:
                if 'id' in meterings_data['attributes']['origin']:
                    meterings_details = {
                        'id': meterings_data['id'],
                        'dsid': meterings_data['attributes']['origin']['id'],
                        'unit': meterings_data['attributes']['unit'],
                        'meterType': meterings_data['attributes']['technicalName'].split()[0],
                        'meterValueType': meterings_data['attributes']['technicalName'].split()[1]
                    }
                    meterings.append(meterings_details)

        return meterings

    def circuits(self):
        meterings = self._meterings
        controllers = self._controllers

        metering_by_dsid = {metering['dsid']: metering for metering in meterings}

        circuits = []
        for controller in controllers:
            if controller['id'] in metering_by_dsid:
                meterid = controller['id']
                meterings = metering_by_dsid[meterid]
                circuit = {
                    "dsid": meterings["dsid"],
                    "meterids": {
                        "power": "dsm-" + meterings["dsid"] + "-power",
                        "energy": "dsm-" + meterings["dsid"] + "-energy"
                    },
                    "name": controller['name'],
                    "hwName": meterings['meterType']
                }
                circuits.append(circuit)

        return circuits

    def zones(self):
        zones_attributes = self.request("zones")['zones']

        zones = []
        for zone in zones_attributes:
            zones_measurements = {}
            if "name" not in zone["attributes"]:
                if zone["id"] == "65534":
                    zone["attributes"]["name"] = "New devices"

            zones_status = self.request("zones/" + zone["id"] + "/status")

            if 'attributes' in zones_status:
                if 'measurements' in zones_status['attributes']:
                    zones_measurements = zones_status['attributes']['measurements']

            cleaned = {
                "id": zone["id"],
                "name": zone["attributes"]["name"],
                "measurements": zones_measurements
            }
            zones.append(cleaned)

        return zones

    def collect_output_devices(self):
        devices_attributes = self.request("dsDevices")
        devices = []
        for device in devices_attributes:
            d = {
                "id": device['id'],
                "name": device['attributes']['name'],
                "present": device['attributes']['present'],
                "zone": ({int(v['id']): v['name'] for v in self._zones}).get(int(device['attributes']['zone']))
            }
            devices.append(d)

        return devices

    def collect_devices_status(self):
        devices_status_attributes = self.request("dsDevices/status")
        devices = []
        for device in devices_status_attributes:
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
                devices.append(d)
        return devices

    def collect(self):
        try:
            self._request_data()
            self._output_devices = self.collect_output_devices()
            self._zones = self.zones()
        except HTTPError as err:
            if err.code == 401:
                fatal('Authentication failure, attempting to restart')
        except URLError as err:
            fatal(err)

        # i = self._appartment['data']
        yield GaugeMetricFamily(
            'dss_appartment_consumption',
            'Current total power consumption [W]', value='444')  # i['attributes']['value'])

        dcc = GaugeMetricFamily(
            'dss_circuit_consumption',
            'Current power consumption per meter [W]',
            labels=["circuit", "hwName"])
        dcm = GaugeMetricFamily(
            'dss_circuit_metervalue',
            'Current measurent of the power consumption [Ws]',
            labels=["circuit", "hwName"])

        circuits_values = self.request("installation/meterings/values")["values"]
        circuits_values_by_meter_id = {circuits_value['id']: circuits_value for circuits_value in circuits_values}

        for circuit in self._circuits:
            circuit_name = circuit['name']
            circuit_type = circuit['hwName']
            circuit_power = (circuits_values_by_meter_id[circuit["meterids"]["power"]])

            dcc.add_metric(
                [circuit_name, circuit_type, circuit['name']], circuit_power["attributes"]["value"])

        for circuit in self._circuits:
            circuit_name = circuit['name']
            circuit_type = circuit['hwName']
            circuit_energy = (circuits_values_by_meter_id[circuit["meterids"]["energy"]])

            dcm.add_metric(
                [circuit_name, circuit_type, circuit['name']], circuit_energy["attributes"]["value"])

        yield dcc
        yield dcm

        ddp = GaugeMetricFamily(
            'dss_device_is_present',
            'Current state of device',
            labels=["device", "zone"])
        for device in self._output_devices:
            device_name = device['name']

            ddp.add_metric(
                [device_name, device['zone'], device_name], device['present'])

        yield ddp

        ddsv = GaugeMetricFamily(
            'dss_device_value',
            'Current function value of device in percent',
            labels=["device", "zone", "type", "value"])
        ddss = GaugeMetricFamily(
            'dss_device_state',
            'Current function status of device. 1 = ok, 2 = moving/dimming',
            labels=["device", "zone", "type", "status"])

        device_states = self.collect_devices_status()
        devices = {device['id']: device for device in self._output_devices}

        for device in device_states:
            device_name = devices[device['id']]['name']
            device_zone = devices[device['id']]['zone']
            ddsv.add_metric(
                [device_name, device_zone, device['type']], round(device['value'], 0))

            state_float = 0
            if device['status'] == "ok":
                state_float = 1
            if device['status'] == "moving":
                state_float = 2
            ddss.add_metric(
                [device_name, device_zone, device['type']], state_float)

        yield ddsv
        yield ddss

        ddzm = GaugeMetricFamily(
            'dss_zone_measurements',
            'Current measurements value of zone - temperature in degree, humidity in percent, '
            'brightness in lux, motion in bool ',
            labels=["zone", "type", "value"])

        zone_states = self._zones
        for zone in zone_states:
            if 'measurements' in zone:
                for measurement, value in zone['measurements'].items():
                    ddzm.add_metric(
                        [zone['name'], measurement], round(value, 0))

        yield ddzm


    def _request_data(self):
        self._appartment = self.request()


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
