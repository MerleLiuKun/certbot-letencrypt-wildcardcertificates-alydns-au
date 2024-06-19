import datetime
import hashlib
import hmac
import json
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

Service = "DNS"
Version = "2018-08-01"
Region = "cn-north-1"
Host = "open.volcengineapi.com"
# 分别将 Access Key ID 和 Secret Access Key 的值传入 AK 变量和 SK 变量
AK = ""
SK = ""


def norm_query(params):
    query = ""
    for key in sorted(params.keys()):
        if type(params[key]) == list:
            for k in params[key]:
                query = (
                        query + quote(key, safe="-_.~") + "=" + quote(k, safe="-_.~") + "&"
                )
        else:
            query = (query + quote(key, safe="-_.~") + "=" + quote(params[key], safe="-_.~") + "&")
    query = query[:-1]
    return query.replace("+", "%20")


# 第一步：准备辅助函数。
# sha256 非对称加密
def hmac_sha256(key: bytes, content: str):
    return hmac.new(key, content.encode("utf-8"), hashlib.sha256).digest()


# sha256 hash算法
def hash_sha256(content: str):
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


# 第二步：创建一个 API 请求函数。签名计算的过程包含在该函数中。
def request(method, query, header, ak, sk, action, body):
    # 第三步：创建身份证明。其中的 Service 和 Region 字段是固定的。ak 和 sk 分别代表
    # AccessKeyID 和 SecretAccessKey。同时需要初始化签名结构体。一些签名计算时需要的属性也在这里处理。
    # 初始化身份证明结构体
    credential = {
        "access_key_id": ak,
        "secret_access_key": sk,
        "service": Service,
        "region": Region,
    }
    # 初始化签名结构体
    query = {"Action": action, "Version": Version, **query}
    sorted_query = OrderedDict(sorted(query.items()))

    request_param = {
        "body": "",
        "host": Host,
        "path": "/",
        "method": method,
        "content_type": "application/json",
        "date": datetime.datetime.utcnow(),
        "query": sorted_query,
    }

    if method == "POST":
        request_param["body"] = json.dumps(body)

    # 第四步：接下来开始计算签名。在计算签名前，先准备好用于接收签算结果的 signResult 变量，并设置一些参数。
    # 初始化签名结果的结构体
    x_date = request_param["date"].strftime("%Y%m%dT%H%M%SZ")
    short_x_date = x_date[:8]
    x_content_sha256 = hash_sha256(request_param["body"])
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
         norm_query(request_param["query"]),
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
    hashed_canonical_request = hash_sha256(canonical_request_str)
    credential_scope = "/".join([short_x_date, credential["region"], credential["service"], "request"])
    string_to_sign = "\n".join(["HMAC-SHA256", x_date, credential_scope, hashed_canonical_request])
    k_date = hmac_sha256(credential["secret_access_key"].encode("utf-8"), short_x_date)
    k_region = hmac_sha256(k_date, credential["region"])
    k_service = hmac_sha256(k_region, credential["service"])
    k_signing = hmac_sha256(k_service, "request")
    signature = hmac_sha256(k_signing, string_to_sign).hex()
    sign_result["Authorization"] = "HMAC-SHA256 Credential={}, SignedHeaders={}, Signature={}".format(
        credential["access_key_id"] + "/" + credential_scope,
        signed_headers_str,
        signature,
    )
    header = {**header, **sign_result}
    # 第六步：将 Signature 签名写入 HTTP Header 中，并发送 HTTP 请求。
    if method == "POST":
        return send("POST", request_param, header)
    if method == "GET":
        return send("GET", request_param, header)


def send(method, request_param, header):
    url = "https://{}{}".format(request_param["host"], request_param["path"])

    # 将数据编码为字节流
    data = urlencode(request_param["body"]).encode()

    # 添加查询参数
    url_with_query = "{}?{}".format(url, urlencode(request_param["query"]))

    # 构建请求对象
    req = urllib_request.Request(url_with_query, data=data, headers=header, method=method)

    # 发送请求并获取响应
    with urllib_request.urlopen(req) as response:
        result = response.read().decode("utf-8")
        return json.loads(result)


if __name__ == "__main__":
    # （GET 请求）调用 ListRecords 接口查询域名的记录列表
    request_query = {"ZID": ""}
    check_zone_result = request("GET", request_query, {}, AK, SK, "ListRecords", {})
    print(check_zone_result)
