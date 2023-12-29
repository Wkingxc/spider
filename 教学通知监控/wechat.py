import requests
import json


# 发送文本消息
def send_text(content, mentioned_list=None, mentioned_mobile_list=None):
    webhook='https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=58fe4dca-7acf-42fb-9f5f-7375abacf614'
    header = {
        "Content-Type": "application/json",
        "Charset": "UTF-8"
    }
    data = {
        "msgtype": "text",
        "text": {
            "content": content, "mentioned_list": mentioned_list, "mentioned_mobile_list": mentioned_mobile_list
        }
    }
    data = json.dumps(data)
    info = requests.post(url=webhook, data=data, headers=header)


# 发送markdown消息
def send_md(webhook, content):
    header = {
        "Content-Type": "application/json",
        "Charset": "UTF-8"
    }
    data = {

        "msgtype": "markdown",
        "markdown": {
            "content": content
        }
    }
    data = json.dumps(data)
    info = requests.post(url=webhook, data=data, headers=header)

send_text('123')