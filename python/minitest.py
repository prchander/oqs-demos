import json
import sys 
import urllib.request 
import ssl 
import os

sslSettings= ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
sslSettings.verify_mode = ssl.CERT_REQUIRED

# Trust LetsEncrypt Root CA to get required files:
sslSettings.load_verify_locations(cafile="isrgrootx1.pem")

with urllib.request.urlopen('https://test.openquantumsafe.org/assignments.json', context=sslSettings) as json_file:
    algos = json.load(json_file)

with urllib.request.urlopen('https://test.openquantumsafe.org/CA.crt', context=sslSettings) as ca_file:
    data = ca_file.read().decode()

with open("CA.crt", "w+") as ca_file:
    ca_file.write(data)

# now switch root CA:
sslSettings.load_verify_locations(cafile="CA.crt")

for sig, kexalgos in algos.items():
    print("Testing Signature Algorithm: " + sig)
    for kexalgo, port in kexalgos.items():
        try:
            if kexalgo != "*": os.environ["TLS_DEFAULT_GROUPS"] = kexalgo
            with urllib.request.urlopen('https://test.openquantumsafe.org:' + str(port), context=sslSettings) as response:
                if response.getcode() == 200:
                    print("Test successful for: " + kexalgo)
                else:
                    print("Test failed with code " + str(response.getcode()) + " for algo: " + kexalgo)
        except urllib.error.URLError as e:
            print("Test failed with code " + str(response.getcode()) + " for algo: " + kexalgo)
            print(e)
        except Exception as e:
            print("Test failed with code " + str(response.getcode()) + " for algo: " + kexalgo)
            print(e)

