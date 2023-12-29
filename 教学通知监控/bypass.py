import cloudscraper
import requests


proxies = {
    'https': 'http://127.0.0.1:7890',
    'http': 'http://127.0.0.1:7890'
}
headers = {
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36',
    'connection': 'close',
}

url = 'https://manga18.club/manhwa/thorns-on-innocence/chapter-19/'
img_url = 'https://s1.manga18.club/manga/thorns-on-innocence/chapters/chapter-54/21.jpg'

scraper=cloudscraper.create_scraper(browser={
        'browser': 'chrome',
        'platform': 'windows',
        'mobile': False
    },disableCloudflareV1=True,delay=10)
resp = scraper.get(img_url,proxies=proxies)
print(resp.status_code)
# with open('./1.jpg','wb') as f:
#     f.write(resp)
