import pprint

import requests
from bs4 import BeautifulSoup

summaryText = []
publishDate = []
softwareType = []
vendor = []
product = []
version = []
cveIDNumber = []


def getCVEDetails(cveid=''):
    cveUrl = 'http://www.cvedetails.com/cve/' + cveid + '/'
    response = requests.get(cveUrl)
    cveHtml = response.content
    soup = BeautifulSoup(cveHtml, "html.parser")
    if soup == '':
        return
    cveIDNumber.append(cveid)
    table = soup.find(id='vulnprodstable')
    cvssTable = soup.find(id='cvssscorestable')
    summarySoup = soup.find('div', class_="cvedetailssummary")
    summaryText.append(summarySoup.text.split("\n")[1])
    dateStr = summarySoup.text.split("\n")[3]
    publishDate.append(dateStr.split("\t")[1].split(":")[1])
    productData = []
    for row in table.findAll('tr')[::-1]:  # Get only the last row
        cols = row.findAll('td')
        for i in range(len(cols)):
            productData.append(cols[i].text.strip())
    softwareType.append(productData[1])
    vendor.append(productData[2])
    product.append(productData[3])
    version.append(productData[4])
    cvssData = []
    for row in cvssTable.findAll('tr'):  # Get only the first row
        cols = row.findAll('td')
        for i in range(len(cols)):
            cvssData.append(cols[i].text.strip())
    pprint.pprint(cvssData)
