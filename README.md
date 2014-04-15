![virustotal-api logo](https://raw.githubusercontent.com/blacktop/virustotal-api/master/doc/logo.png)

virustotal-api
==============

[![PyPI version](https://badge.fury.io/py/virustotal-api.svg)](http://badge.fury.io/py/virustotal-api) [![Build Status](https://travis-ci.org/blacktop/virustotal-api.svg?branch=master)](https://travis-ci.org/blacktop/virustotal-api)

Virus Total Public/Private/Intel API

- https://www.virustotal.com/en/documentation/public-api/
- https://www.virustotal.com/en/documentation/private-api/
- https://www.virustotal.com/intelligence/help/automation/

Installation
-----------

    $ pip install virustotal-api


Usage
-----
```python
import json
import hashlib
from virustotal.virus_total_apis import PublicApi as VirusTotalPublicApi

API_KEY = 'Sign-Up for API Key at virustotal.com'

EICAR = "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
EICAR_MD5 = hashlib.md5(EICAR).hexdigest()

vt = VirusTotalPublicApi(API_KEY)

response =  vt.get_file_report(EICAR_MD5)
print json.dumps(response, sort_keys=False, indent=4)
```

#### Output:
```json
{
    "response_code": 200,
    "results": {
        "scan_id": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f-1397510237",
        "sha1": "3395856ce81f2b7382dee72602f798b642f14140",
        "resource": "44d88612fea8a8f36de82e1278abb02f",
        "response_code": 1,
        "scan_date": "2014-04-14 21:17:17",
        "permalink": "https://www.virustotal.com/file/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f/analysis/1397510237/",
        "verbose_msg": "Scan finished, scan information embedded in this object",
        "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        "positives": 49,
        "total": 51,
        "md5": "44d88612fea8a8f36de82e1278abb02f",
        "scans": {
            "Bkav": {
                "detected": true,
                "version": "1.3.0.4959",
                "result": "DOS.EiracA.Trojan",
                "update": "20140412"
            },
            "MicroWorld-eScan": {
                "detected": true,
                "version": "12.0.250.0",
                "result": "EICAR-Test-File",
                "update": "20140414"
            },
            "nProtect": {
                "detected": true,
                "version": "2014-04-14.02",
                "result": "EICAR-Test-File",
                "update": "20140414"
            },
            "CMC": {
                "detected": true,
                "version": "1.1.0.977",
                "result": "Eicar.test.file",
                "update": "20140411"
            },
            "CAT-QuickHeal": {
                "detected": true,
                "version": "12.00",
                "result": "EICAR.TestFile",
                "update": "20140414"
            },
            "McAfee": {
                "detected": true,
                "version": "6.0.4.564",
                "result": "EICAR test file",
                "update": "20140414"
            },
            "Malwarebytes": {
                "detected": false,
                "version": "1.75.0001",
                "result": null,
                "update": "20140414"
            },
            "TheHacker": {
                "detected": true,
                "version": null,
                "result": "EICAR_Test_File",
                "update": "20140413"
            },
            "K7GW": {
                "detected": true,
                "version": "9.176.11755",
                "result": "EICAR_Test_File",
                "update": "20140414"
            },
            "K7AntiVirus": {
                "detected": true,
                "version": "9.176.11755",
                "result": "EICAR_Test_File",
                "update": "20140414"
            },
            "Agnitum": {
                "detected": true,
                "version": "5.5.1.3",
                "result": "EICAR_test_file",
                "update": "20140414"
            },
            "F-Prot": {
                "detected": true,
                "version": "4.7.1.166",
                "result": "EICAR_Test_File",
                "update": "20140414"
            },
            "Symantec": {
                "detected": true,
                "version": "20131.1.5.61",
                "result": "EICAR Test String",
                "update": "20140414"
            },
            "Norman": {
                "detected": true,
                "version": "7.03.02",
                "result": "EICAR_Test_file_not_a_virus!",
                "update": "20140414"
            },
            "TotalDefense": {
                "detected": true,
                "version": "37.0.10878",
                "result": "the EICAR test string",
                "update": "20140414"
            },
            "TrendMicro-HouseCall": {
                "detected": true,
                "version": "9.700-1001",
                "result": "Eicar_test_file",
                "update": "20140414"
            },
            "Avast": {
                "detected": true,
                "version": "8.0.1489.320",
                "result": "EICAR Test-NOT virus!!!",
                "update": "20140414"
            },
            "ClamAV": {
                "detected": true,
                "version": "0.97.3",
                "result": "Eicar-Test-Signature",
                "update": "20140414"
            },
            "Kaspersky": {
                "detected": true,
                "version": "12.0.0.1225",
                "result": "EICAR-Test-File",
                "update": "20140414"
            },
            "BitDefender": {
                "detected": true,
                "version": "7.2",
                "result": "EICAR-Test-File (not a virus)",
                "update": "20140414"
            },
            "NANO-Antivirus": {
                "detected": true,
                "version": "0.28.0.59288",
                "result": "Marker.Dos.EICAR-Test-File.dyb",
                "update": "20140414"
            },
            "ViRobot": {
                "detected": true,
                "version": "2011.4.7.4223",
                "result": "EICAR-test",
                "update": "20140414"
            },
            "AegisLab": {
                "detected": true,
                "version": "1.5",
                "result": "EICAR-AV-Test",
                "update": "20140414"
            },
            "Ad-Aware": {
                "detected": true,
                "version": "12.0.163.0",
                "result": "EICAR-Test-File (not a virus)",
                "update": "20140414"
            },
            "Emsisoft": {
                "detected": true,
                "version": "3.0.0.596",
                "result": "EICAR-Test-File (not a virus) (B)",
                "update": "20140414"
            },
            "Comodo": {
                "detected": true,
                "version": "18106",
                "result": "Application.EICAR-Test-File",
                "update": "20140414"
            },
            "F-Secure": {
                "detected": true,
                "version": "11.0.19100.45",
                "result": "EICAR_Test_File",
                "update": "20140414"
            },
            "DrWeb": {
                "detected": true,
                "version": "7.00.8.02260",
                "result": "EICAR Test File (NOT a Virus!)",
                "update": "20140414"
            },
            "VIPRE": {
                "detected": true,
                "version": "28228",
                "result": "EICAR (v)",
                "update": "20140414"
            },
            "AntiVir": {
                "detected": true,
                "version": "7.11.143.108",
                "result": "Eicar-Test-Signature",
                "update": "20140414"
            },
            "TrendMicro": {
                "detected": true,
                "version": "9.740-1012",
                "result": "Eicar_test_file",
                "update": "20140414"
            },
            "McAfee-GW-Edition": {
                "detected": true,
                "version": "2013",
                "result": "EICAR test file",
                "update": "20140414"
            },
            "Sophos": {
                "detected": true,
                "version": "4.98.0",
                "result": "EICAR-AV-Test",
                "update": "20140414"
            },
            "Jiangmin": {
                "detected": true,
                "version": "16.0.100",
                "result": "EICAR-Test-File",
                "update": "20140414"
            },
            "Antiy-AVL": {
                "detected": true,
                "version": "0.1.0.1",
                "result": "Trojan/Win32.SGeneric",
                "update": "20140414"
            },
            "Kingsoft": {
                "detected": true,
                "version": "2013.04.09.267",
                "result": "Test.eicar.aa",
                "update": "20140414"
            },
            "Microsoft": {
                "detected": true,
                "version": "1.10401",
                "result": "Virus:DOS/EICAR_Test_File",
                "update": "20140414"
            },
            "SUPERAntiSpyware": {
                "detected": true,
                "version": "5.6.0.1032",
                "result": "NotAThreat.EICAR[TestFile]",
                "update": "20140414"
            },
            "AhnLab-V3": {
                "detected": true,
                "version": "None",
                "result": "EICAR_Test_File",
                "update": "20140414"
            },
            "GData": {
                "detected": true,
                "version": "24",
                "result": "EICAR-Test-File",
                "update": "20140414"
            },
            "Commtouch": {
                "detected": true,
                "version": "5.4.1.7",
                "result": "EICAR_Test_File",
                "update": "20140414"
            },
            "ByteHero": {
                "detected": false,
                "version": "1.0.0.1",
                "result": null,
                "update": "20140414"
            },
            "VBA32": {
                "detected": true,
                "version": "3.12.26.0",
                "result": "EICAR-Test-File",
                "update": "20140414"
            },
            "Baidu-International": {
                "detected": true,
                "version": "3.5.1.41473",
                "result": "EICAR.Test.File",
                "update": "20140414"
            },
            "ESET-NOD32": {
                "detected": true,
                "version": "9676",
                "result": "Eicar test file",
                "update": "20140414"
            },
            "Rising": {
                "detected": true,
                "version": "25.0.0.11",
                "result": "NORMAL:EICAR-Test-File!84776",
                "update": "20140414"
            },
            "Ikarus": {
                "detected": true,
                "version": "T3.1.6.1.0",
                "result": "EICAR-ANTIVIRUS-TESTFILE",
                "update": "20140414"
            },
            "Fortinet": {
                "detected": true,
                "version": "4",
                "result": "EICAR_TEST_FILE",
                "update": "20140413"
            },
            "AVG": {
                "detected": true,
                "version": "13.0.0.3169",
                "result": "EICAR_Test",
                "update": "20140414"
            },
            "Panda": {
                "detected": true,
                "version": "10.0.3.5",
                "result": "EICAR-AV-TEST-FILE",
                "update": "20140414"
            },
            "Qihoo-360": {
                "detected": true,
                "version": "1.0.0.1015",
                "result": "Trojan.Generic",
                "update": "20140414"
            }
        }
    }
}
```

Testing
-------

To run the tests:

    $ ./tests

Contributing
------------

1. Fork it.
2. Create a branch (`git checkout -b my_virus_total_api`)
3. Commit your changes (`git commit -am "Added Something Cool"`)
4. Push to the branch (`git push origin my_virus_total_api`)
5. Open a [Pull Request](https://github.com/blacktop/virustotal-api/pulls)
6. Wait for me to figure out what the heck a pull request is...
