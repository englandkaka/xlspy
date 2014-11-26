#coding=utf-8
import xlrd
import sys

reload(sys)
sys.setdefaultencoding( "utf-8" )

print "[-]Please Wait ...."
fd9=open("ip_high_up.txt","w")
fd8=open("ip_high_down.txt","w")
fd7=open("new_vuls.txt","w")

data1=xlrd.open_workbook("D:\\my-python\\1\\test\\1.xls")
data2=xlrd.open_workbook("D:\\my-python\\1\\test\\2.xls")
ip1_vul_table=data1.sheets()[0]		#1的原始ip及漏洞
ip2_vul_table=data2.sheets()[0]		#2的原始ip及漏洞

ip1_vul_nrows=ip1_vul_table.nrows	#获取1的ip及漏洞的行数
ip1_vul_ncols=ip1_vul_table.ncols	#获取1的ip及漏洞的列数
ip2_vul_nrows=ip2_vul_table.nrows	#获取2的ip及漏洞的行数
ip2_vul_ncols=ip2_vul_table.ncols	#获取2的ip及漏洞的列数

ip1_ora=ip1_vul_table.col_values(2)		#1的原始ip，包含重复
ip2_ora=ip2_vul_table.col_values(2)		#2的原始ip，包含重复

ip1_nosame=list(set(ip1_ora))			#1的去重后的ip，无重复
ip2_nosame=list(set(ip2_ora))			#2的去重后的ip，无重复

class IpVul():
	def __init__(self,ip):
		self.ip_belong = ""
		self.ip = ip
		self.vuls_level = []
		self.vuls = []
	def addvul(self,ip_belong,vuls_level,vuls):
		self.ip_belong = ip_belong
		self.vuls_level.append(vuls_level)
		self.vuls.append(vuls)
	def vuls_amount(self):
		return len(self.vuls_level)
	def vuls_amount_high(self):
		j=0
		for i in self.vuls_level:
			if i == "高":
				j=j+1
		return j
	def vuls_amount_mindium(self):
		j=0
		for i in self.vuls_level:
			if i == "中":
				j=j+1		
		return j
	def printvul(self):
		fd9.writelines(self.ip_belong+"==>"+"\n")
		fd9.writelines(self.ip+":"+"\n")
		for i in xrange(0,len(self.vuls_level)):
			fd9.writelines("\t\t\t\t"+self.vuls_level[i]+"\t")
			fd9.writelines(self.vuls[i]+"\n")
	def printvul_getdown(self):
		fd8.writelines(self.ip_belong+"==>"+"\n")
		fd8.writelines(self.ip+":"+"\n")
		for i in xrange(0,len(self.vuls_level)):
			fd8.writelines("\t\t\t\t\t\t"+self.vuls_level[i]+"\t")
			fd8.writelines(self.vuls[i]+"\n")

def compare_vuls(IpVul1,IpVul2):
    for i in IpVul1.vuls:
    	if i not in IpVul2.vuls:	
			fd7.writelines("\t\t\t\t"+i+"\n")

ip1_vul_list=[]
i=0
for ip1_ss in ip1_nosame:															#获取1本月的以ip为准的IpVul对象列表 ip1_vul_list,对象包含的属性：“所属系统”、“ip”“漏洞风险等级”“漏洞名称”
	ip1_vul_list.append(IpVul(ip1_ss))
	for ip1_rr in xrange(0,ip1_vul_nrows):
		if ip1_vul_table.row_values(ip1_rr)[2] == ip1_ss:
			ip1_vul_list[i].addvul(ip1_vul_table.row_values(ip1_rr)[0],ip1_vul_table.row_values(ip1_rr)[1],ip1_vul_table.row_values(ip1_rr)[3])
	i=i+1

ip2_vul_list=[]
j=0
for ip2_ss in ip2_nosame:															#获取2上月的以ip为准的IpVul对象列表 ip2_vul_list,对象包含的属性：“所属系统”、“ip”“漏洞风险等级”“漏洞名称”
	ip2_vul_list.append(IpVul(ip2_ss))
	for ip2_rr in xrange(0,ip2_vul_nrows):
		if ip2_vul_table.row_values(ip2_rr)[2] == ip2_ss:
			ip2_vul_list[j].addvul(ip2_vul_table.row_values(ip2_rr)[0],ip2_vul_table.row_values(ip2_rr)[1],ip2_vul_table.row_values(ip2_rr)[3])
	j=j+1

fd0 = open("result.txt","w")

fd0.writelines("本月扫描ip数量："+str(len(ip1_vul_list))+"\n")
fd0.writelines("上月扫描ip数量："+str(len(ip2_vul_list))+"\n\n")

sameip = []

for x in ip1_nosame:
	for y in ip2_nosame:
		if x == y:
			sameip.append(x)				#两张表都有的ip列表	sameip
fd0.writelines("本月和上个月都扫描了的ip数量："+str(len(sameip))+" 与上月扫描主机覆盖比例："+str(round(float(len(sameip))/float(len(ip2_nosame)),2))+"\n")

high=0
for i in ip1_vul_list:
	for j in i.vuls_level:
		if j == "高":
			high=high+1
fd0.writelines("本月高风险漏洞数量："+str(high)+" 所占比例："+str(round((float(high)/float(ip1_vul_table.nrows)),2))+"\n\n")


ip_vul_highup = []
highgetup=0
for i in xrange(0,len(ip1_vul_list)):
	for j in xrange(0,len(ip2_vul_list)):
		if (ip2_vul_list[j].ip == ip1_vul_list[i].ip)and(ip1_vul_list[i].vuls_amount()>ip2_vul_list[j].vuls_amount()):
			ip_vul_highup.append(ip1_vul_list[i])
			highgetup=highgetup+1
fd0.writelines("漏洞增加的主机总数："+str(highgetup)+"\t"+" 所占比例："+str(round(float(highgetup)/float(len(ip1_vul_list)),2)))
fd0.writelines("具体系统对应IP见同目录下ip_high_up.txt"+"\n")

ip_vul_highdown = []
highgetdown=0
for i in xrange(0,len(ip1_vul_list)):
	for j in xrange(0,len(ip2_vul_list)):
		if (ip2_vul_list[j].ip == ip1_vul_list[i].ip)and(ip1_vul_list[i].vuls_amount()<ip2_vul_list[j].vuls_amount()):
			ip_vul_highdown.append(ip1_vul_list[i])
			highgetdown=highgetdown+1
fd0.writelines("漏洞减少的主机总数："+str(highgetdown)+"\t"+" 所占比例："+str(round(float(highgetdown)/float(len(ip1_vul_list)),2)))
fd0.writelines("具体系统对应IP见同目录下ip_high_down.txt"+"\n\n")

boss_high = 0
boss_medium = 0
for i in ip1_vul_list:
	if i.ip_belong == "BOSS":
		boss_high=boss_high+i.vuls_amount_high()
		boss_medium=boss_medium+i.vuls_amount_mindium()
fd0.writelines("BOSS系统\n本月高危漏洞数："+str(boss_high)+" 中危漏洞数："+str(boss_medium)+"\n")

oa_high = 0
oa_medium = 0
for i in ip1_vul_list:
	if i.ip_belong == "OA":
		oa_high=oa_high+i.vuls_amount_high()
		oa_medium=oa_medium+i.vuls_amount_mindium()
fd0.writelines("OA系统\n本月高危漏洞数："+str(oa_high)+" 中危漏洞数："+str(oa_medium)+"\n")

jf_high = 0
jf_medium = 0
for i in ip1_vul_list:
	if i.ip_belong == "经分":
		jf_high=jf_high+i.vuls_amount_high()
		jf_medium=jf_medium+i.vuls_amount_mindium()
fd0.writelines("经分系统\n本月高危漏洞数："+str(jf_high)+" 中危漏洞数："+str(jf_medium)+"\n")

kf_high = 0
kf_medium = 0
for i in ip1_vul_list:
	if i.ip_belong == "客服":
		kf_high=kf_high+i.vuls_amount_high()
		kf_medium=kf_medium+i.vuls_amount_mindium()
fd0.writelines("客服系统\n本月高危漏洞数："+str(kf_high)+" 中危漏洞数："+str(kf_medium)+"\n")

fd0.close()

ip_vul_highup = sorted(ip_vul_highup,key=lambda IpVul: IpVul.ip_belong)
for i in ip_vul_highup:
	i.printvul()
ip_vul_highdown = sorted(ip_vul_highdown,key=lambda IpVul: IpVul.ip_belong)
for i in ip_vul_highdown:
	i.printvul_getdown()

for i in ip_vul_highup:
	for j in ip2_vul_list:
		if (i.ip == j.ip) :
    			fd7.writelines(i.ip_belong+"==>"+i.ip+"：\n")
			compare_vuls(i,j)

fd9.close()
fd8.close()
fd7.close()
print "[+]Job Done!"
