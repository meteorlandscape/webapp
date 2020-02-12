# coding:utf-8

import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web
import base64
import hashlib
import json
import marshal
import MySQLdb
import os
import time
import urllib
import uuid

g_port = 8088
g_token = ""


def getPort():
    global g_port
    return g_port


def getToken():
    global g_token
    return g_token


def getResponseJson(data_dict):
    return json.dumps(data_dict)


class TestUser(object):
    def __init__(self, email, psd, fname, lname):
        self.m_email = email
        self.m_password = psd
        self.m_firstname = fname
        self.m_lastname = lname


class UserHandler(tornado.web.RequestHandler):
    def post(self):
        db = DatabaseUtil()
        email = self.get_body_argument("email_address", "")
        psd = self.get_body_argument("password", "")
        first_name = self.get_body_argument("first_name", "")
        last_name = self.get_body_argument("last_name", "")
        if not email:
            print "no email"
            self.set_status(400)
            self.write(getResponseJson({"400": "Sumbit no email"}))
            return
        if email.find("@") < 0 or email.find(".") < 0:
            print "email not format"
            self.set_status(400)
            self.write(getResponseJson({"400": "Email not format"}))
            return

        sql = "SELECT `email`, `password` from `tbl_users` where email = '%s';" % email
        result = db.Start(sql)
        if result and result[0][0] == email:
            print "Email has already exist."
            self.set_status(400)
            self.write(getResponseJson({"400": "Email has already exist."}))
            return

        if len(psd) <= 8 or psd.isalpha() or psd.isdigit():
            print "weak password"
            self.set_status(400)
            self.write(getResponseJson({"400": "Weak Password."}))
            return


        psd_str = hashlib.md5(psd).hexdigest()
        salt_str = hashlib.md5(psd_str + "csye6225").hexdigest()
        uid = uuid.uuid1()
        created_time = int(time.time())
        sql = "INSERT INTO `tbl_users` (`uid`, `email`, `password`, `firstname`, `lastname`, `account_created`, " \
              "`account_updated`) VALUES ('%s', '%s', '%s', '%s', '%s', '%s', '%s');" \
              % (uid, email, salt_str, first_name, last_name, created_time, created_time)
        db.Start(sql)

        sql = "SELECT `uid`, `email`, `firstname`, `lastname`, `account_created`, `account_updated` from `tbl_users` where email = '%s';" % email
        result = db.Start(sql)
        if not result:
            self.set_status(500)
            self.write(getResponseJson({"500": "Web inner error."}))
            return

        uid, email, first_name, last_name, created_time, updated_time = result[0]
        db.Disconnect()
        self.set_status(201)
        self.write(getResponseJson({"uid": uid,
                                    "email_address": email,
                                    "first_name": first_name,
                                    "last_name": last_name,
                                    "account_created": created_time,
                                    "account_updated": updated_time,
                                    }))

    def put(self):
        # Basic Authentication
        authorization = self.request.headers.get('authorization', '')
        print "authorization : %s" % authorization
        if not authorization:
            print "not authorization"
            self.SetAuthHeader()
            return

        authorization_list = authorization.split(" ")
        print authorization_list
        if len(authorization_list) != 2:
            print "not format"
            self.SetAuthHeader()
            return

        auth_str = authorization_list[1]
        auth_str = base64.b64decode(auth_str)
        auth_list = auth_str.split(":")
        if len(auth_list) != 2:
            print "not format either"
            self.SetAuthHeader()
            return

        auth_email, auth_psd = auth_list
        email = self.get_body_argument("email_address")
        firstname = self.get_body_argument("first_name")
        lastname = self.get_body_argument("last_name")
        new_psd = self.get_body_argument("password")
        if auth_email != email:
            print "submit not match information"
            self.set_status(400)
            self.write(getResponseJson({"400": "Cannot update others information"}))
            return

        db = DatabaseUtil()
        sql = "SELECT `email`, `password` from `tbl_users` where email = '%s';" % auth_email
        result = db.Start(sql)
        if not result:
            print "user not exist"
            self.set_status(400)
            self.write(getResponseJson({"400": "Bad Request"}))
            return

        old_psd_str = hashlib.md5(auth_psd).hexdigest()
        old_salt_str = hashlib.md5(old_psd_str + "csye6225").hexdigest()
        if result[0][1] != old_salt_str:
            print "wrong password"
            self.set_status(400)
            self.write(getResponseJson({"400": "Bad Request"}))
            return

        psd_str = hashlib.md5(new_psd).hexdigest()
        salt_str = hashlib.md5(psd_str + "csye6225").hexdigest()
        updated_time = int(time.time())
        sql = "UPDATE `tbl_users` SET `password` = '%s', `firstname` = '%s', `lastname` = '%s', `account_updated` = '%s'" \
              " WHERE `email` = '%s'" % (salt_str, firstname, lastname, updated_time, email)
        db.Start(sql)
        db.Disconnect()
        self.set_status(204)


    def get(self):
        # Basic Authentication
        authorization = self.request.headers.get('authorization', '')
        print "authorization : %s" % authorization
        if not authorization:
            print "not authorization"
            self.SetAuthHeader()
            return

        authorization_list = authorization.split(" ")
        print authorization_list
        if len(authorization_list) != 2:
            print "not format"
            self.SetAuthHeader()
            return

        auth_str = authorization_list[1]
        auth_str = base64.b64decode(auth_str)
        auth_list = auth_str.split(":")
        if len(auth_list) != 2:
            print "not format either"
            self.SetAuthHeader()
            return

        db = DatabaseUtil()
        email, auth_psd = auth_list
        sql = "SELECT `uid`, `email`, `password`, `firstname`, `lastname`, `account_created`, `account_updated` from " \
              "`tbl_users` where email = '%s';" % email
        result = db.Start(sql)
        if not result:
            print "user not exist"
            self.set_status(400)
            self.write(getResponseJson({"400": "Bad request"}))
            return

        uid, _, psd, firstname, lastname, created_time, updated_time = result[0]
        old_psd_str = hashlib.md5(auth_psd).hexdigest()
        old_salt_str = hashlib.md5(old_psd_str + "csye6225").hexdigest()
        if psd != old_salt_str:
            print "wrong password"
            self.set_status(400)
            self.write(getResponseJson({"400": "Bad Request"}))
            return

        db.Disconnect()
        self.set_status(200)
        self.write(getResponseJson({"uid": uid,
                                    "email_address": email,
                                    "first_name": firstname,
                                    "last_name" : lastname,
                                    "account_created": created_time,
                                    "account_updated": updated_time,
                                    }))


    def SetAuthHeader(self):
        self.set_header("www-authenticate", "Basic realm=\"STOP!\"")
        self.set_header("Content-Type", "text/html")
        self.set_status(401)



class BillHandler(tornado.web.RequestHandler):

    def post(self):
        # Basic Authentication
        authorization = self.request.headers.get('authorization', '')
        print "authorization : %s" % authorization
        if not authorization:
            print "not authorization"
            self.SetAuthHeader()
            return

        authorization_list = authorization.split(" ")
        print authorization_list
        if len(authorization_list) != 2:
            print "not format"
            self.SetAuthHeader()
            return

        auth_str = authorization_list[1]
        auth_str = base64.b64decode(auth_str)
        auth_list = auth_str.split(":")
        if len(auth_list) != 2:
            print "not format either"
            self.SetAuthHeader()
            return

        email, auth_psd = auth_list
        db = DatabaseUtil()
        if not email:
            print "no email"
            self.set_status(400)
            self.write(getResponseJson({"400": "Sumbit no email"}))
            return
        if email.find("@") < 0 or email.find(".") < 0:
            print "email not format"
            self.set_status(400)
            self.write(getResponseJson({"400": "Email not format"}))
            return

        sql = "SELECT `email`, `password`, `uid` from `tbl_users` where email = '%s';" % email
        result = db.Start(sql)
        if not result:
            print "user not exist"
            self.set_status(400)
            self.write(getResponseJson({"400": "Bad request"}))
            return

        psd_str = hashlib.md5(auth_psd).hexdigest()
        salt_str = hashlib.md5(psd_str + "csye6225").hexdigest()
        if result[0][1] != salt_str:
            print "wrong password"
            self.set_status(400)
            self.write(getResponseJson({"400": "Bad Request"}))
            return


        vendor = self.get_body_argument("vendor", "")
        bill_date = self.get_body_argument("bill_date", "")
        due_date = self.get_body_argument("due_date", "")
        amount_due = self.get_body_argument("amount_due", "")
        categories = self.get_body_argument("categories", "")
        paymentStatus = self.get_body_argument("paymentStatus", "")
        categories = marshal.dumps(categories)

        bill_id = uuid.uuid1()
        owner_id = result[0][2]
        sql = "INSERT INTO `tbl_bills` (`id`, `owner_id`, `vendor`, `bill_date`, `due_date`, `amount_due`, `categories`," \
              " `paymentStatus`) VALUES ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s'); " \
              % (bill_id, owner_id, vendor, bill_date, due_date, amount_due, categories, paymentStatus)
        db.Start(sql)

        sql = "SELECT `created_ts`, `updated_ts` from `tbl_bills` where `id` = '%s';" % bill_id
        result = db.Start(sql)
        if not result:
            self.set_status(400)
            self.write(getResponseJson({"400": "Bad Request"}))
            return

        created_ts, updated_ts = result[0]
        created_ts = created_ts.strftime("%Y-%m-%d %H:%M:%S")
        updated_ts = updated_ts.strftime("%Y-%m-%d %H:%M:%S")
        db.Disconnect()
        self.set_status(201)
        self.write(getResponseJson({"id": "%s" % bill_id,
                                    "created_ts": created_ts,
                                    "updated_ts": updated_ts,
                                    "owner_id": owner_id,
                                    "vendor": vendor,
                                    "bill_date": bill_date,
                                    "due_date": due_date,
                                    "amount_due": amount_due,
                                    "categories": marshal.loads(categories),
                                    "paymentStatus" : paymentStatus,
                                    }))


    def put(self, bill_id):
        # Basic Authentication
        authorization = self.request.headers.get('authorization', '')
        print "authorization : %s" % authorization
        if not authorization:
            print "not authorization"
            self.SetAuthHeader()
            return

        authorization_list = authorization.split(" ")
        print authorization_list
        if len(authorization_list) != 2:
            print "not format"
            self.SetAuthHeader()
            return

        auth_str = authorization_list[1]
        auth_str = base64.b64decode(auth_str)
        auth_list = auth_str.split(":")
        if len(auth_list) != 2:
            print "not format either"
            self.SetAuthHeader()
            return

        auth_email, auth_psd = auth_list
        sql = "SELECT `email`, `password` from `tbl_users` where email = '%s';" % auth_email
        db = DatabaseUtil()
        result = db.Start(sql)
        if not result:
            print "user not exist"
            self.set_status(404)
            self.write(getResponseJson({"404": "Not Found"}))
            return

        psd_str = hashlib.md5(auth_psd).hexdigest()
        salt_str = hashlib.md5(psd_str + "csye6225").hexdigest()
        if result[0][1] != salt_str:
            print "wrong password"
            self.set_status(400)
            self.write(getResponseJson({"400": "Bad Request"}))
            return

        vendor = self.get_body_argument("vendor", "")
        bill_date = self.get_body_argument("bill_date", "")
        due_date = self.get_body_argument("due_date", "")
        amount_due = self.get_body_argument("amount_due", "")
        categories = self.get_body_argument("categories", "")
        paymentStatus = self.get_body_argument("paymentStatus", "")
        categories = marshal.dumps(categories)
        sql = "UPDATE `tbl_bills` SET `vendor` = '%s', `bill_date` = '%s', `due_date` = '%s', `amount_due` = '%s', " \
              "`categories` = '%s', `paymentStatus` = '%s' WHERE `id` = '%s'"\
              % (vendor, bill_date, due_date, amount_due, categories, paymentStatus, bill_id)
        db.Start(sql)
        db.Disconnect()
        self.set_status(204)


    def get(self, bill_id):
        # Basic Authentication
        authorization = self.request.headers.get('authorization', '')
        print "authorization : %s" % authorization
        if not authorization:
            print "not authorization"
            self.SetAuthHeader()
            return

        authorization_list = authorization.split(" ")
        print authorization_list
        if len(authorization_list) != 2:
            print "not format"
            self.SetAuthHeader()
            return

        auth_str = authorization_list[1]
        auth_str = base64.b64decode(auth_str)
        auth_list = auth_str.split(":")
        if len(auth_list) != 2:
            print "not format either"
            self.SetAuthHeader()
            return

        auth_email, auth_psd = auth_list
        sql = "SELECT `email`, `password` from `tbl_users` where email = '%s';" % auth_email
        db = DatabaseUtil()
        result = db.Start(sql)
        if not result:
            print "user not exist"
            self.set_status(404)
            self.write(getResponseJson({"404": "Not Found"}))
            return

        psd_str = hashlib.md5(auth_psd).hexdigest()
        salt_str = hashlib.md5(psd_str + "csye6225").hexdigest()
        if result[0][1] != salt_str:
            print "wrong password"
            self.set_status(400)
            self.write(getResponseJson({"400": "Bad Request"}))
            return


        sql = "SELECT `id`, `created_ts`, `updated_ts`, `owner_id`, `vendor`, `bill_date`, `due_date`, `amount_due`, " \
              "`categories`, `paymentStatus` from `tbl_bills` where `id` = '%s';" % bill_id
        result = db.Start(sql)
        if not result:
            print "user not exist"
            self.set_status(404)
            self.write(getResponseJson({"404": "Not Found"}))
            return

        print result
        db.Disconnect()
        self.set_status(200)
        self.write(getResponseJson({"id": "%s" % result[0][0],
                                    "created_ts": result[0][1].strftime("%Y-%m-%d %H:%M:%S"),
                                    "updated_ts": result[0][2].strftime("%Y-%m-%d %H:%M:%S"),
                                    "owner_id": result[0][3],
                                    "vendor": result[0][4],
                                    "bill_date": "%s" % result[0][5],
                                    "due_date": "%s" % result[0][6],
                                    "amount_due": result[0][7],
                                    "categories": marshal.loads(result[0][8]),
                                    "paymentStatus" : result[0][9],
                                    }))


    def delete(self, bill_id):
        # Basic Authentication
        authorization = self.request.headers.get('authorization', '')
        print "authorization : %s" % authorization
        if not authorization:
            print "not authorization"
            self.SetAuthHeader()
            return

        authorization_list = authorization.split(" ")
        print authorization_list
        if len(authorization_list) != 2:
            print "not format"
            self.SetAuthHeader()
            return

        auth_str = authorization_list[1]
        auth_str = base64.b64decode(auth_str)
        auth_list = auth_str.split(":")
        if len(auth_list) != 2:
            print "not format either"
            self.SetAuthHeader()
            return

        auth_email, auth_psd = auth_list
        sql = "SELECT `email`, `password` from `tbl_users` where email = '%s';" % auth_email
        db = DatabaseUtil()
        result = db.Start(sql)
        if not result:
            print "user not exist"
            self.set_status(404)
            self.write(getResponseJson({"404": "Not Found"}))
            return

        psd_str = hashlib.md5(auth_psd).hexdigest()
        salt_str = hashlib.md5(psd_str + "csye6225").hexdigest()
        if result[0][1] != salt_str:
            print "wrong password"
            self.set_status(400)
            self.write(getResponseJson({"400": "Bad Request"}))
            return


        sql = "SELECT `id` from `tbl_bills` where `id` = '%s';" % bill_id
        result = db.Start(sql)
        if not result:
            print "bill not exist"
            self.set_status(404)
            self.write(getResponseJson({"404": "Not Found"}))
            return

        sql = "DELETE FROM `tbl_bills` WHERE `id` = '%s'; " % bill_id
        db.Start(sql)
        db.Disconnect()
        self.set_status(204)


    def SetAuthHeader(self):
        self.set_header("www-authenticate", "Basic realm=\"STOP!\"")
        self.set_header("Content-Type", "text/html")
        self.set_status(401)



class BillsHandler(tornado.web.RequestHandler):

    def get(self):
        # Basic Authentication
        authorization = self.request.headers.get('authorization', '')
        print "authorization : %s" % authorization
        if not authorization:
            print "not authorization"
            self.SetAuthHeader()
            return

        authorization_list = authorization.split(" ")
        print authorization_list
        if len(authorization_list) != 2:
            print "not format"
            self.SetAuthHeader()
            return

        auth_str = authorization_list[1]
        auth_str = base64.b64decode(auth_str)
        auth_list = auth_str.split(":")
        if len(auth_list) != 2:
            print "not format either"
            self.SetAuthHeader()
            return

        auth_email, auth_psd = auth_list
        sql = "SELECT `uid`, `password` from `tbl_users` where email = '%s';" % auth_email
        db = DatabaseUtil()
        result = db.Start(sql)
        if not result:
            print "user not exist"
            self.set_status(404)
            self.write(getResponseJson({"404": "Not Found"}))
            return

        uid, db_psd = result[0]
        psd_str = hashlib.md5(auth_psd).hexdigest()
        salt_str = hashlib.md5(psd_str + "csye6225").hexdigest()
        if db_psd != salt_str:
            print "wrong password"
            self.set_status(400)
            self.write(getResponseJson({"400": "Bad Request"}))
            return


        sql = "SELECT `id`, `created_ts`, `updated_ts`, `owner_id`, `vendor`, `bill_date`, `due_date`, `amount_due`, " \
              "`categories`, `paymentStatus` from `tbl_bills` WHERE `owner_id` = '%s';" % uid
        result = db.Start(sql)
        if not result:
            print "bills empty"
            self.set_status(404)
            self.write(getResponseJson({"404": "Not Found"}))
            return

        res_list = []
        for bill_id, created_ts, updated_ts, owner_id, vendor, bill_date, due_date, amount_due, categories, paymentStatus  in result:
            res_list.append({"id": "%s" % bill_id,
                            "created_ts": created_ts.strftime("%Y-%m-%d %H:%M:%S"),
                            "updated_ts": updated_ts.strftime("%Y-%m-%d %H:%M:%S"),
                            "owner_id": owner_id,
                            "vendor": vendor,
                            "bill_date": "%s" % bill_date,
                            "due_date": "%s" % due_date,
                            "amount_due": amount_due,
                            "categories": marshal.loads(categories),
                            "paymentStatus" : paymentStatus,
                            })

        db.Disconnect()
        self.set_status(200)
        self.write(getResponseJson(res_list))


    def SetAuthHeader(self):
        self.set_header("www-authenticate", "Basic realm=\"STOP!\"")
        self.set_header("Content-Type", "text/html")
        self.set_status(401)


class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/v1/user", UserHandler),
            (r"/v1/user/self", UserHandler),
            (r"/v1/bill", BillHandler),
            (r"/v1/bill/(.*)", BillHandler),
            (r"/v1/bills", BillsHandler),
        ]
        settings = dict(
            template_path=os.path.join(os.path.dirname(__file__), "templates"),
            static_path=os.path.join(os.path.dirname(__file__), "static"),
            debug=True,
        )
        tornado.web.Application.__init__(self, handlers, **settings)


class DatabaseUtil(object):
    def __init__(self):
        self.m_ip = "localhost"
        self.m_db_username = "root"
        self.m_db_password = "Jennifer202212"
        self.m_db_name = "csye6225"
        self.m_db = MySQLdb.connect(self.m_ip, self.m_db_username, self.m_db_password, self.m_db_name, charset='utf8')

    def Start(self, sql):
        cursor = self.m_db.cursor()
        cursor.execute(sql)
        self.m_db.commit()
        data = cursor.fetchall()
        return data

    def Disconnect(self):
        self.m_db.close()


if __name__ == "__main__":
    tornado.options.parse_command_line()
    http_server = tornado.httpserver.HTTPServer(Application())
    http_server.listen(getPort())
    tornado.ioloop.IOLoop.instance().start()
