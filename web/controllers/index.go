package controllers

import (
	"encoding/json"
	"github.com/astaxie/beego"
	"github.com/astaxie/beego/logs"
	"github.com/cnlh/nps/lib/file"
	"github.com/cnlh/nps/server"
	"github.com/cnlh/nps/server/tool"
)

type IndexController struct {
	BaseController
}

func (s *IndexController) Index() {
	s.Data["web_base_url"] = beego.AppConfig.String("web_base_url")
	s.Data["data"] = server.GetDashboardData()
	s.SetInfo("dashboard")
	s.display("index/index")
}
func (s *IndexController) Help() {
	s.SetInfo("about")
	s.display("index/help")
}

func (s *IndexController) Tcp() {
	s.SetInfo("tcp")
	s.SetType("tcp")
	s.display("index/list")
}

func (s *IndexController) Udp() {
	s.SetInfo("udp")
	s.SetType("udp")
	s.display("index/list")
}

func (s *IndexController) Socks5() {
	s.SetInfo("socks5")
	s.SetType("socks5")
	s.display("index/list")
}

func (s *IndexController) Http() {
	s.SetInfo("http proxy")
	s.SetType("httpProxy")
	s.display("index/list")
}
func (s *IndexController) File() {
	s.SetInfo("file server")
	s.SetType("file")
	s.display("index/list")
}

func (s *IndexController) Secret() {
	s.SetInfo("secret")
	s.SetType("secret")
	s.display("index/list")
}
func (s *IndexController) P2p() {
	s.SetInfo("p2p")
	s.SetType("p2p")
	s.display("index/list")
}

func (s *IndexController) Host() {
	s.SetInfo("host")
	s.SetType("hostServer")
	s.display("index/list")
}

func (s *IndexController) All() {
	s.Data["menu"] = "client"
	clientId := s.getEscapeString("client_id")
	s.Data["client_id"] = clientId
	s.SetInfo("client id:" + clientId)
	s.display("index/list")
}

func (s *IndexController) GetTunnel() {
	start, length := s.GetAjaxParams()
	taskType := s.getEscapeString("type")
	clientId := s.GetIntNoErr("client_id")
	list, cnt := server.GetTunnel(start, length, taskType, clientId, s.getEscapeString("search"))
	s.AjaxTable(list, cnt, cnt)
}
func (s *IndexController) AddUser() {
	if s.Ctx.Request.Method != "POST" {
		s.AjaxErr("unsupport method type")
	}
	logs.Debug("begin add user")
	var user User
	data := s.Ctx.Input.RequestBody
	auth := s.Ctx.Request.Header.Get("Authorization")
	if err := tool.AuthHeaderAndBody(auth, data); err != nil {
		s.AjaxErr("Auth failed")
	}
	if err := json.Unmarshal(data, &user); err != nil {
		s.AjaxErr(err.Error())
	}

	pass, err := tool.AesDPassGet(user.PassWord)
	if err != nil {
		s.AjaxErr(err.Error())
	}
	var result bool
	if beego.AppConfig.String("redis_cluster") == "true" {
		rdb, err := tool.GetCluster()
		if err != nil {
			logs.Debug("get redis cluster failed, error is %s", err)
			s.AjaxErr(err.Error())
		}
		result, err = rdb.SetNX(user.Name, pass, 0).Result()
		_ = rdb.Close()
		if !result {
			s.AjaxErr("user:" + user.Name + " already exist")
		}
		if err != nil {
			s.AjaxErr(err.Error())
		}
	} else {
		rdb, err := tool.GetRdb()
		if err != nil {
			s.AjaxErr(err.Error())
		}
		result, err = rdb.SetNX(user.Name, pass, 0).Result()
		_ = rdb.Close()
		if !result {
			s.AjaxErr("user:" + user.Name + "already exist")
		}
		if err != nil {
			s.AjaxErr(err.Error())
		}
	}
	logs.Debug("end add user")
	s.AjaxOk("add user success")
}
func (s *IndexController) ModifyUser() {
	if s.Ctx.Request.Method != "PUT" {
		s.AjaxErr("unsupport method type")
	}
	logs.Debug("begin modify user")
	var user User
	data := s.Ctx.Input.RequestBody
	auth := s.Ctx.Request.Header.Get("Authorization")
	if err := tool.AuthHeaderAndBody(auth, data); err != nil {
		s.AjaxErr("Auth failed")
	}
	if err := json.Unmarshal(data, &user); err != nil {
		s.AjaxErr(err.Error())
	}
	pass, err := tool.AesDPassGet(user.PassWord)
	if err != nil {
		s.AjaxErr(err.Error())
	}
	if beego.AppConfig.String("redis_cluster") == "true" {
		rdb, err := tool.GetCluster()
		if err != nil {
			logs.Debug("get redis cluster failed, error is %s", err)
			s.AjaxErr(err.Error())
		}
		err = rdb.Set(user.Name, pass, 0).Err()
		_ = rdb.Close()
		if err != nil {
			s.AjaxErr(err.Error())
		}
	} else {
		rdb, err := tool.GetRdb()
		if err != nil {
			s.AjaxErr(err.Error())
		}
		err = rdb.Set(user.Name, pass, 0).Err()
		_ = rdb.Close()
		if err != nil {
			s.AjaxErr(err.Error())
		}
	}
	logs.Debug("end modify user")
	s.AjaxOk("modify user success")

}
func (s *IndexController) MuxAddUser() {
	if s.Ctx.Request.Method != "POST" {
		s.AjaxErr("unsupport method type")
	}
	logs.Debug("begin mux add  user")
	var users MuxUser
	auth := s.Ctx.Request.Header.Get("Authorization")
	data := s.Ctx.Input.RequestBody
	if err := tool.AuthHeaderAndBody(auth, data); err != nil {
		s.AjaxErr("Auth failed")
	}
	if err := json.Unmarshal(data, &users); err != nil {
		s.AjaxErr(err.Error())
	}
	if beego.AppConfig.String("redis_cluster") == "true" {
		rdb, err := tool.GetCluster()
		if err != nil {
			logs.Debug("get redis cluster failed, error is %s", err)
			s.AjaxErr(err.Error())
		}
		for _, user := range users.Users {
			pass, err := tool.AesDPassGet(user.PassWord)
			if err != nil {
				_ = rdb.Close()
				s.AjaxErr(err.Error())
			}
			result, err := rdb.SetNX(user.Name, pass, 0).Result()
			if !result {
				_ = rdb.Close()
				s.AjaxErr("user:" + user.Name + " already exist")
			}
			if err != nil {
				_ = rdb.Close()
				s.AjaxErr(err.Error())
			}

		}
		_ = rdb.Close()
	} else {
		var cmd []interface{}
		for _, user := range users.Users {
			pass, err := tool.AesDPassGet(user.PassWord)
			if err != nil {
				s.AjaxErr(err.Error())
			}
			cmd = append(cmd, user.Name)
			cmd = append(cmd, pass)
		}
		rdb, err := tool.GetRdb()
		if err != nil {
			s.AjaxErr(err.Error())
		}
		result, _ := rdb.MSetNX(cmd...).Result()
		if !result {
			for _, user := range users.Users {
				value := rdb.Get(user.Name)
				if "" != value.Val() {
					_ = rdb.Close()
					s.AjaxErr("user:" + user.Name + "already exist")
				}
			}
		}
		_ = rdb.Close()
	}
	logs.Debug("end mux add  user")
	s.AjaxOk("mux add user success")

}
func (s *IndexController) MuxModifyUser() {
	if s.Ctx.Request.Method != "PUT" {
		s.AjaxErr("unsupport method type")
	}
	logs.Debug("begin mux modify user")
	var users MuxUser
	data := s.Ctx.Input.RequestBody
	auth := s.Ctx.Request.Header.Get("Authorization")
	if err := tool.AuthHeaderAndBody(auth, data); err != nil {
		s.AjaxErr("Auth failed")
	}
	if err := json.Unmarshal(data, &users); err != nil {
		s.AjaxErr(err.Error())
	}
	if beego.AppConfig.String("redis_cluster") == "true" {
		rdb, err := tool.GetCluster()
		if err != nil {
			logs.Debug("get redis cluster failed, error is %s", err)
			s.AjaxErr(err.Error())
		}
		for _, user := range users.Users {
			pass, err := tool.AesDPassGet(user.PassWord)
			if err != nil {
				_ = rdb.Close()
				s.AjaxErr(err.Error())
			}
			err = rdb.Set(user.Name, pass, 0).Err()
			if err != nil {
				_ = rdb.Close()
				s.AjaxErr(err.Error())
			}
		}
		_ = rdb.Close()
	} else {
		var cmd []interface{}
		for _, user := range users.Users {
			pass, err := tool.AesDPassGet(user.PassWord)
			if err != nil {
				s.AjaxErr(err.Error())
			}
			cmd = append(cmd, user.Name)
			cmd = append(cmd, pass)
		}
		rdb, err := tool.GetRdb()
		if err != nil {
			s.AjaxErr(err.Error())
		}
		err = rdb.MSet(cmd...).Err()
		if err != nil {
			_ = rdb.Close()
			s.AjaxErr(err.Error())
		}
		_ = rdb.Close()
	}
	logs.Debug("end mux modify user")
	s.AjaxOk("mux modify user success")
}

func (s *IndexController) MuxDelUser() {
	if s.Ctx.Request.Method != "DELETE" {
		s.AjaxErr("unsupport method type")
	}
	logs.Debug("begin mux delete user")
	var users MuxUser
	data := s.Ctx.Input.RequestBody
	auth := s.Ctx.Request.Header.Get("Authorization")
	if err := tool.AuthHeaderAndBody(auth, data); err != nil {
		s.AjaxErr("Auth failed")
	}
	if err := json.Unmarshal(data, &users); err != nil {
		s.AjaxErr(err.Error())
	}
	if beego.AppConfig.String("redis_cluster") == "true" {
		rdb, err := tool.GetCluster()
		if err != nil {
			logs.Debug("get redis cluster failed, error is %s", err)
			s.AjaxErr(err.Error())
		}
		for _, user := range users.Users {
			err := rdb.Del(user.Name).Err()
			if err != nil {
				_ = rdb.Close()
				s.AjaxErr(err.Error())
			}
		}
		_ = rdb.Close()
	} else {
		rdb, err := tool.GetRdb()
		if err != nil {
			s.AjaxErr(err.Error())
		}
		for _, user := range users.Users {
			err = rdb.Del(user.Name).Err()
			if err != nil {
				_ = rdb.Close()
				s.AjaxErr(err.Error())
			}
		}
		_ = rdb.Close()
	}
	logs.Debug("end mux delete user")
	s.AjaxOk("mux delete user success")
}
func (s *IndexController) DelUser() {
	if s.Ctx.Request.Method != "DELETE" {
		s.AjaxErr("unsupport method type")
	}
	logs.Debug("begin delete user")
	var user User
	data := s.Ctx.Input.RequestBody
	auth := s.Ctx.Request.Header.Get("Authorization")
	if err := tool.AuthHeaderAndBody(auth, data); err != nil {
		s.AjaxErr("Auth failed")
	}
	if err := json.Unmarshal(data, &user); err != nil {
		s.AjaxErr(err.Error())
	}
	if beego.AppConfig.String("redis_cluster") == "true" {
		rdb, err := tool.GetCluster()
		if err != nil {
			logs.Debug("get redis cluster failed, error is %s", err)
			s.AjaxErr(err.Error())
		}
		err = rdb.Del(user.Name).Err()
		_ = rdb.Close()
		if err != nil {
			s.AjaxErr(err.Error())
		}
	} else {
		rdb, err := tool.GetRdb()
		if err != nil {
			s.AjaxErr(err.Error())
		}
		err = rdb.Del(user.Name).Err()
		_ = rdb.Close()
		if err != nil {
			s.AjaxErr(err.Error())
		}
	}
	logs.Debug("end delete user")
	s.AjaxOk(" delete user success")
}

func (s *IndexController) GetUser() {
	if s.Ctx.Request.Method != "GET" {
		s.AjaxErr("unsupport method type")
	}
	logs.Debug("begin get user")
	query := s.Ctx.Input.Query("username")

	if beego.AppConfig.String("redis_cluster") == "true" {
		rdb, err := tool.GetCluster()
		if err != nil {
			logs.Debug("get redis cluster failed, error is %s", err)
			s.AjaxErr(err.Error())
		}
		value := rdb.Get(query)
		_ = rdb.Close()
		if "" == value.Val() {
			s.AjaxErr("user does not exist")
		}
	} else {
		rdb, err := tool.GetRdb()
		if err != nil {
			s.AjaxErr(err.Error())
		}
		value := rdb.Get(query)
		_ = rdb.Close()
		if "" == value.Val() {
			s.AjaxErr("user does not exist")
		}
	}
	logs.Debug("end get user")
	s.AjaxOk("user exists")
}
func (s *IndexController) Add() {
	if s.Ctx.Request.Method == "GET" {
		s.Data["type"] = s.getEscapeString("type")
		s.Data["client_id"] = s.getEscapeString("client_id")
		s.SetInfo("add tunnel")
		s.display()
	} else {
		t := &file.Tunnel{
			Port:      s.GetIntNoErr("port"),
			ServerIp:  s.getEscapeString("server_ip"),
			Mode:      s.getEscapeString("type"),
			Target:    &file.Target{TargetStr: s.getEscapeString("target"), LocalProxy: s.GetBoolNoErr("local_proxy")},
			Id:        int(file.GetDb().JsonDb.GetTaskId()),
			Status:    true,
			Remark:    s.getEscapeString("remark"),
			Password:  s.getEscapeString("password"),
			LocalPath: s.getEscapeString("local_path"),
			StripPre:  s.getEscapeString("strip_pre"),
			Flow:      &file.Flow{},
		}
		if !tool.TestServerPort(t.Port, t.Mode) {
			s.AjaxErr("The port cannot be opened because it may has been occupied or is no longer allowed.")
		}
		var err error
		if t.Client, err = file.GetDb().GetClient(s.GetIntNoErr("client_id")); err != nil {
			s.AjaxErr(err.Error())
		}
		if t.Client.MaxTunnelNum != 0 && t.Client.GetTunnelNum() >= t.Client.MaxTunnelNum {
			s.AjaxErr("The number of tunnels exceeds the limit")
		}
		if err := file.GetDb().NewTask(t); err != nil {
			s.AjaxErr(err.Error())
		}
		if err := server.AddTask(t); err != nil {
			s.AjaxErr(err.Error())
		} else {
			s.AjaxOk("add success")
		}
	}
}
func (s *IndexController) GetOneTunnel() {
	id := s.GetIntNoErr("id")
	data := make(map[string]interface{})
	if t, err := file.GetDb().GetTask(id); err != nil {
		data["code"] = 0
	} else {
		data["code"] = 1
		data["data"] = t
	}
	s.Data["json"] = data
	s.ServeJSON()
}
func (s *IndexController) Edit() {
	id := s.GetIntNoErr("id")
	if s.Ctx.Request.Method == "GET" {
		if t, err := file.GetDb().GetTask(id); err != nil {
			s.error()
		} else {
			s.Data["t"] = t
		}
		s.SetInfo("edit tunnel")
		s.display()
	} else {
		if t, err := file.GetDb().GetTask(id); err != nil {
			s.error()
		} else {
			if client, err := file.GetDb().GetClient(s.GetIntNoErr("client_id")); err != nil {
				s.AjaxErr("modified error,the client is not exist")
				return
			} else {
				t.Client = client
			}
			if s.GetIntNoErr("port") != t.Port {
				if !tool.TestServerPort(s.GetIntNoErr("port"), t.Mode) {
					s.AjaxErr("The port cannot be opened because it may has been occupied or is no longer allowed.")
					return
				}
				t.Port = s.GetIntNoErr("port")
			}
			t.ServerIp = s.getEscapeString("server_ip")
			t.Mode = s.getEscapeString("type")
			t.Target = &file.Target{TargetStr: s.getEscapeString("target")}
			t.Password = s.getEscapeString("password")
			t.Id = id
			t.LocalPath = s.getEscapeString("local_path")
			t.StripPre = s.getEscapeString("strip_pre")
			t.Remark = s.getEscapeString("remark")
			t.Target.LocalProxy = s.GetBoolNoErr("local_proxy")
			file.GetDb().UpdateTask(t)
			server.StopServer(t.Id)
			server.StartTask(t.Id)
		}
		s.AjaxOk("modified success")
	}
}

func (s *IndexController) Stop() {
	id := s.GetIntNoErr("id")
	if err := server.StopServer(id); err != nil {
		s.AjaxErr("stop error")
	}
	s.AjaxOk("stop success")
}

func (s *IndexController) Del() {
	id := s.GetIntNoErr("id")
	if err := server.DelTask(id); err != nil {
		s.AjaxErr("delete error")
	}
	s.AjaxOk("delete success")
}

func (s *IndexController) Start() {
	id := s.GetIntNoErr("id")
	if err := server.StartTask(id); err != nil {
		s.AjaxErr("start error")
	}
	s.AjaxOk("start success")
}

func (s *IndexController) HostList() {
	if s.Ctx.Request.Method == "GET" {
		s.Data["client_id"] = s.getEscapeString("client_id")
		s.Data["menu"] = "host"
		s.SetInfo("host list")
		s.display("index/hlist")
	} else {
		start, length := s.GetAjaxParams()
		clientId := s.GetIntNoErr("client_id")
		list, cnt := file.GetDb().GetHost(start, length, clientId, s.getEscapeString("search"))
		s.AjaxTable(list, cnt, cnt)
	}
}

func (s *IndexController) GetHost() {
	if s.Ctx.Request.Method == "POST" {
		data := make(map[string]interface{})
		if h, err := file.GetDb().GetHostById(s.GetIntNoErr("id")); err != nil {
			data["code"] = 0
		} else {
			data["data"] = h
			data["code"] = 1
		}
		s.Data["json"] = data
		s.ServeJSON()
	}
}

func (s *IndexController) DelHost() {
	id := s.GetIntNoErr("id")
	if err := file.GetDb().DelHost(id); err != nil {
		s.AjaxErr("delete error")
	}
	s.AjaxOk("delete success")
}

func (s *IndexController) AddHost() {
	if s.Ctx.Request.Method == "GET" {
		s.Data["client_id"] = s.getEscapeString("client_id")
		s.Data["menu"] = "host"
		s.SetInfo("add host")
		s.display("index/hadd")
	} else {
		h := &file.Host{
			Id:           int(file.GetDb().JsonDb.GetHostId()),
			Host:         s.getEscapeString("host"),
			Target:       &file.Target{TargetStr: s.getEscapeString("target"), LocalProxy: s.GetBoolNoErr("local_proxy")},
			HeaderChange: s.getEscapeString("header"),
			HostChange:   s.getEscapeString("hostchange"),
			Remark:       s.getEscapeString("remark"),
			Location:     s.getEscapeString("location"),
			Flow:         &file.Flow{},
			Scheme:       s.getEscapeString("scheme"),
			KeyFilePath:  s.getEscapeString("key_file_path"),
			CertFilePath: s.getEscapeString("cert_file_path"),
		}
		var err error
		if h.Client, err = file.GetDb().GetClient(s.GetIntNoErr("client_id")); err != nil {
			s.AjaxErr("add error the client can not be found")
		}
		if err := file.GetDb().NewHost(h); err != nil {
			s.AjaxErr("add fail" + err.Error())
		}
		s.AjaxOk("add success")
	}
}

func (s *IndexController) EditHost() {
	id := s.GetIntNoErr("id")
	if s.Ctx.Request.Method == "GET" {
		s.Data["menu"] = "host"
		if h, err := file.GetDb().GetHostById(id); err != nil {
			s.error()
		} else {
			s.Data["h"] = h
		}
		s.SetInfo("edit")
		s.display("index/hedit")
	} else {
		if h, err := file.GetDb().GetHostById(id); err != nil {
			s.error()
		} else {
			if h.Host != s.getEscapeString("host") {
				tmpHost := new(file.Host)
				tmpHost.Host = s.getEscapeString("host")
				tmpHost.Location = s.getEscapeString("location")
				tmpHost.Scheme = s.getEscapeString("scheme")
				if file.GetDb().IsHostExist(tmpHost) {
					s.AjaxErr("host has exist")
					return
				}
			}
			if client, err := file.GetDb().GetClient(s.GetIntNoErr("client_id")); err != nil {
				s.AjaxErr("modified error,the client is not exist")
			} else {
				h.Client = client
			}
			h.Host = s.getEscapeString("host")
			h.Target = &file.Target{TargetStr: s.getEscapeString("target")}
			h.HeaderChange = s.getEscapeString("header")
			h.HostChange = s.getEscapeString("hostchange")
			h.Remark = s.getEscapeString("remark")
			h.Location = s.getEscapeString("location")
			h.Scheme = s.getEscapeString("scheme")
			h.KeyFilePath = s.getEscapeString("key_file_path")
			h.CertFilePath = s.getEscapeString("cert_file_path")
			h.Target.LocalProxy = s.GetBoolNoErr("local_proxy")
			file.GetDb().JsonDb.StoreHostToJsonFile()
		}
		s.AjaxOk("modified success")
	}
}
