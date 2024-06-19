import datetime
import hashlib
import hmac
import json
import os
import sys
from collections import OrderedDict

pv = "python2"
if sys.version_info[0] < 3:
    from urllib import quote
    from urllib import urlencode
else:
    from urllib.parse import quote
    from urllib.parse import urlencode
    from urllib import request as urllib_request

    pv = "python3"


class Volcengine:
    VC_SERVICE = "DNS"
    VC_VERSION = "2018-08-01"
    VC_REGION = "cn-north-1"
    VC_HOST = "open.volcengineapi.com"

    def __init__(self, access_key_id, access_key_secret, domain_name):
        self.ak = access_key_id
        self.sk = access_key_secret
        self.domain_name = domain_name

    @staticmethod
    def norm_query(params):
        query = ""
        for key in sorted(params.keys()):
            if isinstance(params[key], list):
                for k in params[key]:
                    query += (quote(key, safe="-_.~") + "=" + quote(str(k), safe="-_.~") + "&")
            else:
                query += (quote(key, safe="-_.~") + "=" + quote(str(params[key]), safe="-_.~") + "&")
        query = query[:-1]  # Remove the trailing '&'
        return query.replace("+", "%20")

    # sha256 非对称加密
    @staticmethod
    def hmac_sha256(key: bytes, content: str):
        return hmac.new(key, content.encode("utf-8"), hashlib.sha256).digest()

    # sha256 hash算法
    @staticmethod
    def hash_sha256(content: str):
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def request(self, method, query, header, action, body):
        # 第三步：创建身份证明。其中的 Service 和 Region 字段是固定的。ak 和 sk 分别代表
        # AccessKeyID 和 SecretAccessKey。同时需要初始化签名结构体。一些签名计算时需要的属性也在这里处理。
        # 初始化身份证明结构体
        credential = {
            "access_key_id": self.ak,
            "secret_access_key": self.sk,
            "service": self.VC_SERVICE,
            "region": self.VC_REGION,
        }
        # 初始化签名结构体
        query = {"Action": action, "Version": self.VC_VERSION, **query}
        sorted_query = OrderedDict(sorted(query.items()))

        request_param = {
            "body": "",
            "host": self.VC_HOST,
            "path": "/",
            "method": method,
            "content_type": "application/json",
            "date": datetime.datetime.utcnow(),
            "query": sorted_query,
        }

        if method == "POST":
            # request_param["body"] = json.dumps(body)
            request_param["body"] = urlencode(body)

        # 第四步：接下来开始计算签名。在计算签名前，先准备好用于接收签算结果的 signResult 变量，并设置一些参数。
        # 初始化签名结果的结构体
        x_date = request_param["date"].strftime("%Y%m%dT%H%M%SZ")
        short_x_date = x_date[:8]
        x_content_sha256 = self.hash_sha256(request_param["body"])
        sign_result = {
            "Host": request_param["host"],
            "X-Content-Sha256": x_content_sha256,
            "X-Date": x_date,
            "Content-Type": request_param["content_type"],
        }
        # 第五步：计算 Signature 签名。
        signed_headers_str = ";".join(
            ["content-type", "host", "x-content-sha256", "x-date"]
        )
        canonical_request_str = "\n".join(
            [request_param["method"],
             request_param["path"],
             self.norm_query(request_param["query"]),
             "\n".join(
                 [
                     "content-type:" + request_param["content_type"],
                     "host:" + request_param["host"],
                     "x-content-sha256:" + x_content_sha256,
                     "x-date:" + x_date,
                 ]
             ),
             "",
             signed_headers_str,
             x_content_sha256,
             ]
        )
        hashed_canonical_request = self.hash_sha256(canonical_request_str)
        credential_scope = "/".join([short_x_date, credential["region"], credential["service"], "request"])
        string_to_sign = "\n".join(["HMAC-SHA256", x_date, credential_scope, hashed_canonical_request])
        k_date = self.hmac_sha256(credential["secret_access_key"].encode("utf-8"), short_x_date)
        k_region = self.hmac_sha256(k_date, credential["region"])
        k_service = self.hmac_sha256(k_region, credential["service"])
        k_signing = self.hmac_sha256(k_service, "request")
        signature = self.hmac_sha256(k_signing, string_to_sign).hex()
        sign_result["Authorization"] = "HMAC-SHA256 Credential={}, SignedHeaders={}, Signature={}".format(
            credential["access_key_id"] + "/" + credential_scope,
            signed_headers_str,
            signature,
        )
        header = {**header, **sign_result}

        url = "https://{}{}".format(request_param["host"], request_param["path"])
        # 添加查询参数
        url_with_query = "{}?{}".format(url, urlencode(request_param["query"]))

        # 将数据编码为字节流
        data = request_param["body"].encode()

        # 构建请求对象
        req = urllib_request.Request(url_with_query, data=data, headers=header, method=method)

        # 发送请求并获取响应
        with urllib_request.urlopen(req) as response:
            result = response.read().decode("utf-8")
            return json.loads(result)

    @staticmethod
    def get_domain(domain_name):
        domain_parts = domain_name.split('.')
        if len(domain_parts) > 2:
            dirpath = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
            domainfile = dirpath + "/domain.ini"
            domainarr = []
            with open(domainfile) as f:
                for line in f:
                    val = line.strip()
                    domainarr.append(val)
            rootdomain = '.'.join(domain_parts[-(2 if domain_parts[-1] in domainarr else 3):])
            selfdomain = domain_name.split(rootdomain)[0]
            return selfdomain[0:len(selfdomain) - 1], rootdomain
        return "", domain_name

    def list_domains(self):
        request_query = {"PageSize": 100}
        result = self.request(
            method="GET",
            query=request_query,
            header={},
            action="ListZones",
            body={}
        )
        return result

    def add_domain_record(self, zid, rr, value):
        request_body = {"ZID": zid, "Host": rr, "Type": "TXT", "Value": value}
        result = self.request(
            method="POST",
            query={},
            header={},
            action="CreateRecord",
            body=request_body,
        )
        return result

    def list_domain_record(self, zid):
        request_query = {"ZID": zid, "PageSize": 100}
        result = self.request(
            method="GET",
            query=request_query,
            header={},
            action="ListRecords",
            body={},
        )
        return result

    def delete_domain_record(self, record_id):
        request_body = {"RecordID": record_id}
        result = self.request(
            method="POST",
            query={},
            header={},
            action="DeleteRecord",
            body=request_body,
        )
        return result


if __name__ == "__main__":
    print(f"域名 API 调用开始")
    print("-".join(sys.argv))

    file_name, cmd, certbot_domain, acme_challenge, certbot_validation, ACCESS_KEY_ID, ACCESS_KEY_SECRET = sys.argv

    certbot_domain = Volcengine.get_domain(certbot_domain)
    print(certbot_domain)
    if certbot_domain[0] == "":
        selfdomain = acme_challenge
    else:
        selfdomain = acme_challenge + "." + certbot_domain[0]

    domain = Volcengine(ACCESS_KEY_ID, ACCESS_KEY_SECRET, certbot_domain[1])

    # 获取ZID
    zid = None
    domains_resp = domain.list_domains()
    all_domains = domains_resp["Result"]["Zones"]
    for d in all_domains:
        if d["ZoneName"] == domain.domain_name:
            zid = d["ZID"]

    if not zid:
        print(f"获取ZID失败")
        sys.exit(0)

    if cmd == "add":
        domain.add_domain_record(
            zid=zid,
            rr=selfdomain,
            value=certbot_validation,
        )
        print("域名解析添加完毕")
    elif cmd == "clean":
        data = domain.list_domain_record(zid=zid)
        records = data.get("Result", {}).get("Records", [])
        for record in records:
            if record["Host"] == selfdomain:
                domain.delete_domain_record(record["RecordID"])

        print("域名解析删除完毕")

    print("域名调用结束")

