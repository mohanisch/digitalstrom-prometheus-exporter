# digitalstrom-prometheus-exporter

The exporter currently collects from the dSS the power consumption and status of individual devices.

```
# HELP dss_circuit_consumption Current power consumption [W]
# TYPE dss_circuit_consumption gauge
dss_circuit_consumption{circuit="circuit livingroom",fstype="fsname"} 7.0

# HELP dss_circuit_metervalue Current measurent of the power consumption [Ws]
# TYPE dss_circuit_metervalue gauge
dss_circuit_metervalue{circuit="circuit livingroom",fstype="fsname"} 1.5145362e+07
# HELP dss_device_is_present Current state of device
# TYPE dss_device_is_present gauge
dss_device_is_present{device="livingroom_ceiling_lamp ",fstype="fsname"} 1.0
```

### Preparation
#### Obtaining appToken
```https://dss.local:8080/json/system/requestApplicationToken?applicationName=prometheus_exporter```

```
GET /json/system/requestApplicationToken?applicationName=Example {
”ok” : true, ”result” :
{
”applicationToken” : ”4fa07386c77d7f32260066c83b58aece5814698376bd03f0e3b5764e58f0ec1a” }
}
```

#### Login with admin user
```curl -k https://dss.local:8080/json/system/login?user=dssadmin\&password=PAssWorD```

Result:
```
GET /json/system/login?user=dssadmin\&password=dssadmin {
”ok” : true,
”result” : { ”token” : ”cea026b6f9d69e57e030736076285da77dbf117d24dbec69e349b2fb4ab7425e” } }
```

#### Enable new application token
```
curl -k \
  --header 'Cookie: token=cea026b6f9d69e57e030736076285da77dbf117d24dbec69e349b2fb4ab7425e' \
https://dss.local:8080/json/system/enableToken?applicationToken=4fa07386c77d7f32260066c83b58aece5814698376bd03f0e3b5764e58f0ec1a
```


### Usage
```
docker run -d -p 9184:9184 -e DSS_LOGINTOKEN=4fa07386c77d7f32260066c83b58aece5814698376bd03f0e3b5764e58f0ec1a marcohansch/dss_prometheus_exporter
```

### CHANGELOG
#### 0.1
initial commi