#coding:utf-8

DATA_LIST = [('04d6c0a8-4337-11ea-8c89-005056360ada','2020-01-30 08:03:37','2020-01-30 08:03:37','12b047ee-4332-11ea-8c89-005056360ada','Northeastern University','2020-01-06','2020-01-12',7000.51,["college", "tuition", "spring2020"],'paid'),('1590cede-4337-11ea-8c89-005056360ada','2020-01-30 08:04:05','2020-01-30 08:04:05','12b047ee-4332-11ea-8c89-005056360ada','Northeastern University','2020-01-06','2020-01-12',7000.51,["college", "tuition", "spring2020"],'paid'),('1a14cdaa-4334-11ea-8c89-005056360ada','2020-01-30 07:42:44','2020-01-30 07:42:44','12b047ee-4332-11ea-8c89-005056360ada','Northeastern University','2020-01-06','2020-01-12',7000.51,["college", "tuition", "spring2020"],'paid'),('34f356be-4334-11ea-8c89-005056360ada','2020-01-30 07:43:29','2020-01-30 07:43:29','12b047ee-4332-11ea-8c89-005056360ada','Northeastern University','2020-01-06','2020-01-12',7000.51,["college", "tuition", "spring2020"],'paid'),('47a861c4-4333-11ea-8c89-005056360ada','2020-01-30 07:36:51','2020-01-30 07:36:51',)]

#Test
def TestDbUtil():
	db = DatabaseUtil()
	sql = "select * from `tbl_bills`;"
	print DATA_LIST
	db.Disconnect()

class DatabaseUtil(object):
    def __init__(self):
        self.m_ip = "localhost"
        self.m_db_username = "root"
        self.m_db_password = "Jennifer202212"
        self.m_db_name = "csye6225"


    def Start(self, sql):
		cursor = self.m_db.cursor()
		if 1:
			return
		cursor.execute(sql)
		self.m_db.commit()
		data = cursor.fetchall()
		return data

    def Disconnect(self):
		fp = open("./test-results/results.txt","w")
		fp.write("%s" % DATA_LIST)
		fp.close()


if __name__ == "__main__":
	TestDbUtil()
