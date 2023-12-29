import requests
from lxml import etree
from datetime import datetime
import json
import time

headers = {
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36',
    'connection': 'close',
}

# 发送给微信机器人


def send_text(content, mentioned_list=None, mentioned_mobile_list=None):
    webhook = 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=58fe4dca-7acf-42fb-9f5f-7375abacf614'
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


articles = []
# 监测网站今天是否有新的通知公告
def monitor():
    url = 'https://ce.xidian.edu.cn/sy/tzgg.htm'
    r = requests.get(url, headers=headers)
    if r.status_code == 200:
        tree = etree.HTML(r.content)
        article = tree.xpath("//li[@id='line_u8_0']/a")[1]
        news_title = article.xpath("./p")[0].text
        news_date = article.xpath("./i")[0].text
        if news_date == datetime.now().strftime('%Y-%m-%d'):
            if news_title not in articles:
                articles.append(news_title)
                content = f'网信院最新通知公告：{news_title}'
                wechat.send_text(content)


n=0
while True:
    n+=1
    send_text(f'test{n}')
    time.sleep(5)