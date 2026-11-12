package refrigeration

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const maxBody = 64 << 10

type xmlElement struct {
	Name     string
	Attrs    []xml.Attr
	Text     string
	Children []xmlElement
}

func attr(name, value string) xml.Attr { return xml.Attr{Name: xml.Name{Local: name}, Value: value} }
func element(name, text string, attrs ...xml.Attr) xmlElement {
	return xmlElement{Name: name, Text: text, Attrs: attrs}
}
func children(name string, values ...xmlElement) xmlElement {
	return xmlElement{Name: name, Children: values}
}
func (e xmlElement) value(name string) string {
	for _, a := range e.Attrs {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}
func (e xmlElement) child(name string) *xmlElement {
	for i := range e.Children {
		if e.Children[i].Name == name {
			return &e.Children[i]
		}
	}
	return nil
}

func (e xmlElement) MarshalXML(enc *xml.Encoder, _ xml.StartElement) error {
	start := xml.StartElement{Name: xml.Name{Local: e.Name}, Attr: e.Attrs}
	if err := enc.EncodeToken(start); err != nil {
		return err
	}
	if e.Text != "" {
		if err := enc.EncodeToken(xml.CharData([]byte(e.Text))); err != nil {
			return err
		}
	}
	for _, c := range e.Children {
		if err := enc.Encode(c); err != nil {
			return err
		}
	}
	return enc.EncodeToken(start.End())
}

func encodeElement(e xmlElement) ([]byte, error) {
	var out bytes.Buffer
	out.WriteString(xml.Header)
	enc := xml.NewEncoder(&out)
	if err := enc.Encode(e); err != nil {
		return nil, err
	}
	if err := enc.Flush(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func parseCommand(data []byte) (xmlElement, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = true
	var root xmlElement
	stack := []*xmlElement{}
	tokens := 0
	finished := false
	for {
		token, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return root, err
		}
		tokens++
		if tokens > 2048 {
			return root, errors.New("XML token limit")
		}
		switch t := token.(type) {
		case xml.Directive:
			return root, errors.New("XML directives are not accepted")
		case xml.ProcInst:
			if t.Target != "xml" || tokens != 1 {
				return root, errors.New("XML processing instruction")
			}
		case xml.StartElement:
			if finished || len(stack) >= 4 || t.Name.Space != "" || len(t.Attr) > 24 {
				return root, errors.New("XML shape limit")
			}
			e := xmlElement{Name: t.Name.Local, Attrs: t.Attr}
			seen := map[string]bool{}
			for _, a := range t.Attr {
				if a.Name.Space != "" || len(a.Name.Local) > 64 || len(a.Value) > 1024 || seen[a.Name.Local] {
					return root, errors.New("XML attribute limit")
				}
				seen[a.Name.Local] = true
			}
			if len(stack) == 0 {
				if t.Name.Local != "cmd" {
					return root, errors.New("expected cmd")
				}
				root = e
				stack = append(stack, &root)
			} else {
				parent := stack[len(stack)-1]
				if len(parent.Children) >= 100 {
					return root, errors.New("XML child limit")
				}
				parent.Children = append(parent.Children, e)
				stack = append(stack, &parent.Children[len(parent.Children)-1])
			}
		case xml.CharData:
			if len(stack) == 0 {
				if strings.TrimSpace(string(t)) != "" {
					return root, errors.New("trailing XML text")
				}
			} else {
				e := stack[len(stack)-1]
				if len(e.Text)+len(t) > 4096 {
					return root, errors.New("XML text limit")
				}
				e.Text += string(t)
			}
		case xml.EndElement:
			if len(stack) == 0 {
				return root, errors.New("unexpected XML end")
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				finished = true
			}
		}
	}
	if !finished || len(stack) != 0 || root.value("action") == "" || len(root.value("action")) > 64 {
		return root, errors.New("incomplete XML command")
	}
	return root, nil
}

func readCommand(w http.ResponseWriter, r *http.Request) (xmlElement, string, error) {
	if encoding := r.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		return xmlElement{}, "", errors.New("compressed request not accepted")
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	raw := bounded(string(body), 4096)
	if err != nil {
		return xmlElement{}, raw, err
	}
	kind, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil && r.Header.Get("Content-Type") != "" {
		return xmlElement{}, raw, err
	}
	switch kind {
	case "application/x-www-form-urlencoded":
		form, err := url.ParseQuery(string(body))
		if err != nil || len(form["xml"]) != 1 {
			return xmlElement{}, raw, errors.New("expected one xml form field")
		}
		body = []byte(form.Get("xml"))
		raw = bounded(string(body), 4096)
	case "", "text/xml", "application/xml", "text/plain":
	default:
		return xmlElement{}, raw, errors.New("unsupported media type")
	}
	cmd, err := parseCommand(body)
	return cmd, raw, err
}

func (s *Server) xmlResponse(w http.ResponseWriter, r *http.Request, e xmlElement, compress string, status int) {
	data, err := encodeElement(e)
	if err != nil {
		http.Error(w, "Unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "close")
	if compress == "1" || compress != "0" && len(data) > 1024 && acceptsGzip(r.Header.Get("Accept-Encoding")) {
		var out bytes.Buffer
		gz := gzip.NewWriter(&out)
		if _, err = gz.Write(data); err == nil {
			err = gz.Close()
		}
		if err != nil {
			http.Error(w, "Unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Add("Vary", "Accept-Encoding")
		data = out.Bytes()
	}
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

func acceptsGzip(header string) bool {
	for _, part := range strings.Split(header, ",") {
		fields := strings.Split(strings.TrimSpace(part), ";")
		if fields[0] != "gzip" {
			continue
		}
		enabled := true
		for _, p := range fields[1:] {
			if strings.HasPrefix(strings.TrimSpace(p), "q=") {
				q, err := strconv.ParseFloat(strings.TrimPrefix(strings.TrimSpace(p), "q="), 64)
				if err != nil || q <= 0 {
					enabled = false
				}
			}
		}
		if enabled {
			return true
		}
	}
	return false
}

func response(action string, code int) xmlElement {
	return element("resp", "", attr("action", action), attr("error", strconv.Itoa(code)))
}

func suspicious(value string) bool {
	value = strings.ToLower(value)
	for _, needle := range []string{"<!doctype", "<!entity", "../", "..\\", "/etc/passwd", "$(", "cmd.exe", "/bin/sh", ";wget", ";curl", "<script", "union select"} {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

func (s *Server) handleXML(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		s.xmlResponse(w, r, response("", 11), "0", http.StatusMethodNotAllowed)
		return
	}
	cmd, raw, err := readCommand(w, r)
	action := cmd.value("action")
	if suspicious(raw) || suspicious(r.URL.RawQuery) {
		s.record(r, "exploit.attempt", action, "", "", raw, false, 0, nil)
	}
	if err != nil {
		status := http.StatusOK
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		s.record(r, "malformed", action, "", "", raw, false, 0, map[string]any{"reason": "invalid_xml"})
		s.xmlResponse(w, r, response(action, 9), "0", status)
		return
	}
	if action == "getauth" {
		s.login(w, r, cmd, raw)
		return
	}
	user, password, explicit := requestCredentials(r, cmd)
	auth, ok := s.cookieSession(r)
	if explicit {
		role, valid := s.authenticate(user, password)
		auth = session{User: user, Role: role}
		ok = valid
		if valid && !s.record(r, "auth.success", action, user, password, "", true, 0, map[string]any{"role": role}) {
			s.xmlResponse(w, r, response(action, 4), "0", http.StatusServiceUnavailable)
			return
		}
	}
	write := writeAction(action)
	if !ok || write && !sameOrigin(r) {
		kind := "read"
		if write {
			kind = "write.denied"
		}
		s.record(r, kind, action, user, "", raw, false, 0, map[string]any{"reason": "authorization"})
		if explicit {
			s.record(r, "auth.failed", action, user, password, "", false, 0, nil)
		}
		s.xmlResponse(w, r, response(action, 15), cmd.value("compress"), http.StatusOK)
		return
	}
	if write {
		if !s.record(r, "write.attempt", action, auth.User, "", raw, false, 0, map[string]any{"role": auth.Role}) {
			s.xmlResponse(w, r, response(action, 4), "0", http.StatusServiceUnavailable)
			return
		}
	}
	s.mu.Lock()
	if s.closed || s.failure != nil {
		s.mu.Unlock()
		s.xmlResponse(w, r, response(action, 4), "0", http.StatusServiceUnavailable)
		return
	}
	old := clonePlant(s.plant)
	advanced := s.plant.advance(s.now())
	result, code, changed, node := s.dispatch(cmd, auth)
	limited := false
	if code == 0 && changed && !s.writes.take(s.clock()) {
		// Over the write budget: the change is undone and nothing is saved.
		s.plant = old
		changed, advanced, limited = false, false, true
		code = 4
		result = response(action, code)
	}
	if code == 0 && (changed || advanced) {
		if err = s.saveLocked(); err != nil {
			if !stateCommitted(err) {
				s.plant = old
			}
			code = 4
			result = response(action, code)
			s.cfg.Logger.Error("persist refrigeration command", "error", err)
		}
	} else if code != 0 && changed {
		s.plant = old
	}
	s.mu.Unlock()
	if err != nil {
		s.fail(err)
	}
	kind := "read"
	if write {
		if code == 0 {
			kind = "write.success"
		} else {
			kind = "write.denied"
		}
	}
	if action == "write_alarm_ack" && code == 0 {
		kind = "alarm"
	}
	meta := map[string]any{"role": auth.Role, "result": code}
	if limited {
		meta["reason"] = "rate"
	}
	if !s.record(r, kind, action, auth.User, "", raw, code == 0, node, meta) {
		s.xmlResponse(w, r, response(action, 4), "0", http.StatusServiceUnavailable)
		return
	}
	if limited {
		w.Header().Set("Retry-After", "1")
		s.xmlResponse(w, r, result, "0", http.StatusServiceUnavailable)
		return
	}
	if err != nil {
		s.xmlResponse(w, r, result, "0", http.StatusServiceUnavailable)
		return
	}
	s.xmlResponse(w, r, result, cmd.value("compress"), http.StatusOK)
}

func clonePlant(p plant) plant {
	p.Devices = append([]device(nil), p.Devices...)
	p.History = append([]sample(nil), p.History...)
	p.Alarms = append([]alarm(nil), p.Alarms...)
	return p
}

func requestCredentials(r *http.Request, cmd xmlElement) (string, string, bool) {
	if header := r.Header.Get("AKSM-Auth"); header != "" {
		if !strings.HasPrefix(header, "Basic ") || len(header) > 1024 {
			return "", "", true
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(header, "Basic "))
		if err != nil {
			return "", "", true
		}
		user, password, ok := strings.Cut(string(decoded), ":")
		if !ok {
			return "", "", true
		}
		return user, password, true
	}
	user := cmd.value("user")
	password := cmd.value("password")
	if password == "" {
		password = cmd.value("pass")
	}
	return user, password, user != "" || password != ""
}

func (s *Server) login(w http.ResponseWriter, r *http.Request, cmd xmlElement, raw string) {
	if len(cmd.Children) > 0 || strings.TrimSpace(cmd.Text) != "" {
		if !s.record(r, "malformed", "getauth", "", "", raw, false, 0, map[string]any{"reason": "shape"}) {
			s.xmlResponse(w, r, response("getauth", 4), "0", http.StatusServiceUnavailable)
			return
		}
		s.xmlResponse(w, r, response("getauth", 3), "0", http.StatusOK)
		return
	}
	if !sameOrigin(r) {
		if !s.record(r, "auth.failed", "getauth", "", "", raw, false, 0, map[string]any{"reason": "origin"}) {
			s.xmlResponse(w, r, response("getauth", 4), "0", http.StatusServiceUnavailable)
			return
		}
		s.xmlResponse(w, r, response("getauth", 15), "0", http.StatusForbidden)
		return
	}
	user, password, _ := requestCredentials(r, cmd)
	role, ok := s.authenticate(user, password)
	out := response("getauth", 15)
	var cookie *http.Cookie
	if ok {
		token, err := s.newSession(user, role)
		if err != nil {
			s.xmlResponse(w, r, response("getauth", 4), "0", http.StatusServiceUnavailable)
			return
		}
		cookie = &http.Cookie{Name: "SMSESSION", Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 1800, Expires: s.now().Add(30 * time.Minute)}
		mask, level := "917504", "3" // Legacy menu and history read access.
		if role == "supervisor" {
			mask = "16777215"
			level = "1"
		} else if role == "operator" {
			mask = "933888" // Read baseline plus alarm acknowledgement.
			level = "2"
		}
		out = response("getauth", 0)
		out.Children = []xmlElement{element("authorization", "01-02"), element("language", "English"), element("authtype", mask), element("access", "01-02"), element("accesslevel", level), element("strongpassword", "0")}
	}
	kind := "auth.failed"
	if ok {
		kind = "auth.success"
	}
	if !s.record(r, kind, "getauth", user, password, raw, ok, 0, map[string]any{"role": role}) {
		s.xmlResponse(w, r, response("getauth", 4), "0", http.StatusServiceUnavailable)
		return
	}
	if cookie != nil {
		http.SetCookie(w, cookie)
	}
	s.xmlResponse(w, r, out, cmd.value("compress"), http.StatusOK)
}

func writeAction(action string) bool {
	switch action {
	case "write_val", "set_defrost", "set_main_switch", "write_alarm_ack":
		return true
	}
	return false
}

func (s *Server) dispatch(cmd xmlElement, auth session) (xmlElement, int, bool, int) {
	action := cmd.value("action")
	fail := func(code int, node int) (xmlElement, int, bool, int) {
		return response(action, code), code, false, node
	}
	out := response(action, 0)
	if strings.TrimSpace(cmd.Text) != "" {
		return fail(3, 0)
	}
	if action != "read_val" && action != "write_val" && action != "read_history" && len(cmd.Children) > 0 {
		return fail(3, 0)
	}
	if units := strings.ToUpper(cmd.value("units")); units != "" && units != "S" && units != "U" {
		return fail(3, 0)
	}
	switch action {
	case "read_units":
		i := s.plant.Identity
		out.Children = []xmlElement{element("total", "1"), element("store_name", i.StoreName), element("unit_name", i.UnitName), element("storeId1", i.Serial[:8]), element("storeId2", i.Serial[len(i.Serial)-8:]), element("software", Firmware), element("macaddr", i.MAC), children("unit", element("addr", "1"), element("ip", i.LANAddress()), element("port", strconv.Itoa(unitPort)))}
	case "read_parm_info":
		if cmd.value("device_id") != "084B8020_015B" {
			return fail(37, 0)
		}
		if tag := cmd.value("tag"); tag != "" && tag != "1" {
			return fail(3, 0)
		}
		out.Attrs = append(out.Attrs, attr("device_id", "084B8020_015B"))
		ps := parameters(s.plant.Devices[0])
		catalog := element("parms", "", attr("count", strconv.Itoa(len(ps))))
		for _, p := range ps {
			rw := "R"
			if p.Writable {
				rw = "W"
			}
			attrs := []xml.Attr{attr("tag", p.Tag), attr("name", p.Name), attr("cid", strconv.Itoa(p.CID)), attr("vid", strconv.Itoa(p.VID)), attr("rw", rw), attr("group", "1")}
			format := func(v float64) string { return decimal(v) }
			if p.Digital {
				attrs = append(attrs, attr("dyn_list_name", "Off/On"), attr("type", "int"))
				format = func(v float64) string {
					if cmd.value("num_only") == "1" {
						return strconv.Itoa(int(v))
					}
					if v == 0 {
						return "Off"
					}
					return "On"
				}
			} else {
				attrs = append(attrs, attr("unit", "degc"), attr("type", "float"))
			}
			attrs = append(attrs, attr("min", format(p.Min)), attr("max", format(p.Max)), attr("default", format(p.Default)))
			if p.Writable {
				attrs = append(attrs, attr("setting", "true"))
			} else {
				attrs = append(attrs, attr("meas", "true"))
			}
			catalog.Children = append(catalog.Children, element("parm", "", attrs...))
		}
		out.Children = []xmlElement{catalog}
	case "read_dyn_list_info":
		if cmd.value("device_id") != "084B8020_015B" {
			return fail(37, 0)
		}
		out.Attrs = append(out.Attrs, attr("device_id", "084B8020_015B"))
		list := element("dyn_list", "", attr("name", "Off/On"), attr("count", "2"))
		list.Children = []xmlElement{element("t", "Off"), element("v", "0"), element("t", "On"), element("v", "1")}
		out.Children = []xmlElement{children("dyn_lists", list)}
		out.Children[0].Attrs = []xml.Attr{attr("count", "1")}
	case "read_devices":
		if len(cmd.Children) > 0 {
			return fail(3, 0)
		}
		out.Children = []xmlElement{element("unit_name", s.plant.Identity.UnitName), element("software", Firmware), element("store_name", s.plant.Identity.StoreName)}
		for _, d := range s.plant.Devices {
			count := s.activeAlarms(d.Node)
			e := element("device", "", attr("alarm", strconv.Itoa(boolInt(count > 0))), attr("ctrl_val", temperature(d.Setpoint, cmd)), attr("indent", "0"), attr("mod", "0"), attr("defrost", strconv.Itoa(boolInt(d.Defrost))), attr("modelname", "AK-CC550-B-015B"), attr("multicasename", d.Name), attr("state", strconv.Itoa(boolInt(d.MainSwitch))), attr("node", strconv.Itoa(d.Node)), attr("nodetype", "16"), attr("online", strconv.Itoa(boolInt(d.Online))), attr("point", "0"), attr("status", d.status()), attr("value", temperature(d.Temperature, cmd)), attr("rack_id", "1"), attr("suction_id", "1"), attr("condenser", "0"))
			e.Children = []xmlElement{element("name", d.Name), element("device_id", "084B8020_015B"), element("type", "EVAP"), element("rack_id", "1")}
			out.Children = append(out.Children, e)
		}
		out.Children = append(out.Children, element("total", strconv.Itoa(len(s.plant.Devices))))
	case "read_device":
		d, code := s.requestDevice(cmd)
		if code != 0 {
			return fail(code, 0)
		}
		out.Attrs = append(out.Attrs, deviceAttrs(d.Node)...)
		out.Children = []xmlElement{element("name", d.Name), element("type", "EVAP"), element("filename", "084B8020.edf"), element("model", "AK-CC550-B-015B"), element("device_id", "084B8020_015B"), element("val", temperature(d.Temperature, cmd)), element("stat", d.status()), element("alarm", strconv.Itoa(s.activeAlarms(d.Node))), element("mainswitch", "1"), element("lights", "0"), element("night", "0"), element("defrost", "1"), element("cleaning", "0"), element("shutdown", "0"), element("host", "1"), element("nodetype", "16"), element("multi", "0"), element("addr", strconv.Itoa(d.Node)), element("node", strconv.Itoa(d.Node)), element("mod", "0"), element("point", "0")}
		return out, 0, false, d.Node
	case "read_val", "write_val":
		if len(cmd.Children) == 0 || len(cmd.Children) > 100 {
			return fail(3, 0)
		}
		if action == "write_val" && auth.Role != "supervisor" {
			return fail(15, 0)
		}
		// Validate the entire batch before committing any values.
		type selected struct {
			d     *device
			p     parameter
			input xmlElement
			value float64
		}
		picks := []selected{}
		seen := map[string]bool{}
		for _, v := range cmd.Children {
			if v.Name != "val" || len(v.Children) > 0 || strings.TrimSpace(v.Text) != "" {
				return fail(3, 0)
			}
			d, code := s.requestDevice(v)
			if code != 0 {
				return fail(code, 0)
			}
			p, ok := findParameter(*d, v)
			if !ok {
				return fail(14, d.Node)
			}
			if !d.Online {
				return fail(63, d.Node)
			}
			value := p.Value
			field := v.value("field")
			if field == "" {
				field = cmd.value("field")
			}
			if field != "" && field != "min" && field != "max" && field != "default" && field != "all" {
				return fail(3, d.Node)
			}
			if action == "write_val" {
				if field != "" {
					return fail(2, d.Node)
				}
				if !p.Writable {
					return fail(2, d.Node)
				}
				n, err := strconv.ParseFloat(v.value("set"), 64)
				if err != nil || !finite(n) {
					return fail(2, d.Node)
				}
				if strings.ToUpper(cmd.value("units")) == "U" && !p.Digital {
					n = (n - 32) * 5 / 9
				}
				if n < p.Min || n > p.Max {
					return fail(2, d.Node)
				}
				value = n
			}
			key := strconv.Itoa(d.Node) + "/" + p.Tag
			if action == "read_val" {
				key += "/" + field
			}
			if seen[key] {
				return fail(3, d.Node)
			}
			seen[key] = true
			picks = append(picks, selected{d, p, v, value})
		}
		node := 0
		changed := false
		for _, pick := range picks {
			if action == "write_val" {
				changed = changed || pick.d.Setpoint != pick.value || pick.p.Value != pick.value
				pick.d.Setpoint = pick.value
				pick.p.Value = pick.value
			}
			e := parameterElement(pick.d.Node, pick.p, pick.input, cmd)
			if action == "write_val" {
				e.Attrs = append(e.Attrs, attr("online", "TRUE"))
			}
			out.Children = append(out.Children, e)
			node = pick.d.Node
		}
		return out, 0, changed, node
	case "set_defrost", "set_main_switch":
		if auth.Role != "supervisor" {
			return fail(15, 0)
		}
		d, code := s.requestDevice(cmd)
		if code != 0 {
			return fail(code, 0)
		}
		if !d.Online {
			return fail(63, d.Node)
		}
		operation := cmd.value("operation")
		if operation != "0" && operation != "1" {
			return fail(3, d.Node)
		}
		if len(cmd.Children) > 0 {
			return fail(3, d.Node)
		}
		before := *d
		if action == "set_defrost" {
			if operation == "1" && !d.MainSwitch {
				return fail(2, d.Node)
			}
			d.Defrost = operation == "1"
			if d.Defrost {
				d.DefrostUntil = s.now().Add(20 * time.Minute)
				d.Compressor = false
			} else {
				d.DefrostUntil = time.Time{}
			}
		} else {
			d.MainSwitch = operation == "1"
			if !d.MainSwitch {
				d.Compressor = false
				d.Defrost = false
				d.DefrostUntil = time.Time{}
			}
		}
		out.Attrs = append(out.Attrs, deviceAttrs(d.Node)...)
		out.Attrs = append(out.Attrs, attr("operation", operation))
		out.Children = []xmlElement{element("operation", "Success")}
		changed := d.Defrost != before.Defrost || d.MainSwitch != before.MainSwitch ||
			d.Compressor != before.Compressor || !d.DefrostUntil.Equal(before.DefrostUntil)
		return out, 0, changed, d.Node
	case "read_date_time":
		out.Children = dateFields(s.now())
	case "alarm_summary", "read_device_alarms":
		return s.alarmSummary(cmd)
	case "alarm_detail":
		return s.alarmDetail(cmd)
	case "write_alarm_ack":
		if auth.Role != "supervisor" && auth.Role != "operator" {
			return fail(15, 0)
		}
		raw := cmd.value("ref")
		ref, err := strconv.Atoi(raw)
		if raw != "all" && (err != nil || ref < 1) {
			return fail(12, 0)
		}
		found, changed := false, false
		for i := range s.plant.Alarms {
			a := &s.plant.Alarms[i]
			if raw != "all" && a.Ref != ref {
				continue
			}
			found = true
			text := "success"
			if a.Acknowledged {
				text = "acknowledged"
			}
			changed = changed || !a.Acknowledged
			a.Acknowledged = true
			out.Children = append(out.Children, element("alarm", text, attr("ref", strconv.Itoa(a.Ref))))
		}
		if !found && raw != "all" {
			return fail(12, 0)
		}
		return out, 0, changed, 0
	case "read_history":
		return s.history(cmd)
	default:
		return fail(11, 0)
	}
	return out, 0, false, 0
}

func (s *Server) requestDevice(e xmlElement) (*device, int) {
	if v := e.value("nodetype"); v != "" && v != "16" {
		return nil, 14
	}
	for _, name := range []string{"mod", "point"} {
		if v := e.value(name); v != "" && v != "0" {
			return nil, 14
		}
	}
	node, err := strconv.Atoi(e.value("node"))
	if err != nil {
		return nil, 3
	}
	d := s.plant.find(node)
	if d == nil {
		return nil, 14
	}
	return d, 0
}

func deviceAttrs(node int) []xml.Attr {
	return []xml.Attr{attr("nodetype", "16"), attr("node", strconv.Itoa(node)), attr("mod", "0"), attr("point", "0")}
}

func findParameter(d device, e xmlElement) (parameter, bool) {
	tag := e.value("tag")
	if tag != "" && (e.value("cid") != "" || e.value("vid") != "") {
		return parameter{}, false
	}
	for _, p := range parameters(d) {
		if tag != "" && tag == p.Tag || tag == "" && e.value("cid") == strconv.Itoa(p.CID) && e.value("vid") == strconv.Itoa(p.VID) {
			return p, true
		}
	}
	return parameter{}, false
}

func temperature(value float64, cmd xmlElement) string {
	unit := "°C"
	if strings.ToUpper(cmd.value("units")) == "U" {
		unit = "°F"
	}
	text := numericTemperature(value, cmd.value("units"))
	if cmd.value("num_only") != "1" {
		text += " " + unit
	}
	return text
}

func numericTemperature(value float64, units string) string {
	if strings.EqualFold(units, "U") {
		value = value*9/5 + 32
	}
	return decimal(value)
}

func parameterElement(node int, p parameter, input, cmd xmlElement) xmlElement {
	attrs := deviceAttrs(node)
	if input.value("tag") != "" {
		attrs = append(attrs, attr("tag", p.Tag))
	} else {
		attrs = append(attrs, attr("cid", strconv.Itoa(p.CID)), attr("vid", strconv.Itoa(p.VID)))
	}
	attrs = append(attrs, attr("display", p.Name), attr("name", p.Name), attr("stat", "Online"), attr("statcode", "2"))
	format := func(v float64) string {
		if p.Digital {
			return strconv.Itoa(int(v))
		}
		return temperature(v, cmd)
	}
	e := element("val", format(p.Value), attrs...)
	field := input.value("field")
	if field == "" {
		field = cmd.value("field")
	}
	if field == "all" {
		e.Text = ""
		e.Children = []xmlElement{element("value", format(p.Value)), element("min", format(p.Min)), element("max", format(p.Max)), element("def", format(p.Default))}
	} else if field == "min" {
		e.Text = format(p.Min)
	} else if field == "max" {
		e.Text = format(p.Max)
	} else if field == "default" {
		e.Text = format(p.Default)
	}
	if field != "" {
		e.Attrs = append(e.Attrs, attr("field", field))
	}
	return e
}

func (s *Server) activeAlarms(node int) int {
	n := 0
	for _, a := range s.plant.Alarms {
		if a.Node == node && a.Active {
			n++
		}
	}
	return n
}

func dateFields(t time.Time) []xmlElement {
	return []xmlElement{element("year", fmt.Sprintf("%02d", t.Year()%100)), element("month", fmt.Sprintf("%02d", int(t.Month()))), element("day", fmt.Sprintf("%02d", t.Day())), element("hour", fmt.Sprintf("%02d", t.Hour())), element("minute", fmt.Sprintf("%02d", t.Minute())), element("second", fmt.Sprintf("%02d", t.Second())), element("epoch", strconv.FormatInt(t.Unix(), 10)), element("timezone", "0"), element("daylightsavings", "0")}
}

func parseDate(e *xmlElement, fallback time.Time) (time.Time, bool) {
	if e == nil {
		return fallback, true
	}
	values := map[string]int{}
	for _, name := range []string{"year", "month", "day", "hour", "minute", "second"} {
		child := e.child(name)
		if child == nil {
			return time.Time{}, false
		}
		n, err := strconv.Atoi(strings.TrimSpace(child.Text))
		if err != nil {
			return time.Time{}, false
		}
		values[name] = n
	}
	year := values["year"]
	if year >= 0 && year < 100 {
		year += 2000
	}
	if year < 2000 || year > 2100 || values["month"] < 1 || values["month"] > 12 || values["day"] < 1 || values["day"] > 31 || values["hour"] < 0 || values["hour"] > 23 || values["minute"] < 0 || values["minute"] > 59 || values["second"] < 0 || values["second"] > 59 {
		return time.Time{}, false
	}
	t := time.Date(year, time.Month(values["month"]), values["day"], values["hour"], values["minute"], values["second"], 0, time.UTC)
	return t, t.Day() == values["day"]
}

func (s *Server) history(cmd xmlElement) (xmlElement, int, bool, int) {
	fail := func(code int) (xmlElement, int, bool, int) { return response("read_history", code), code, false, 0 }
	d, code := s.requestDevice(cmd)
	if code != 0 {
		return fail(code)
	}
	p, ok := findParameter(*d, cmd)
	if !ok {
		return fail(16)
	}
	start, ok := parseDate(cmd.child("starttime"), s.now().Add(-6*time.Hour))
	if !ok {
		return fail(3)
	}
	stop, ok := parseDate(cmd.child("stoptime"), s.now())
	if !ok || stop.Before(start) {
		return fail(3)
	}
	rate := 3600
	if raw := cmd.value("sample_rate"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 86400 {
			return fail(3)
		}
		rate = n
	}
	if rate < 60 {
		rate = 60
	}
	rate = ((rate + 59) / 60) * 60
	selected := []sample{}
	var last time.Time
	for _, h := range s.plant.History {
		if h.Node != d.Node || h.Time.Before(start) || h.Time.After(stop) || !last.IsZero() && h.Time.Sub(last) < time.Duration(rate)*time.Second {
			continue
		}
		selected = append(selected, h)
		last = h.Time
	}
	if len(selected) == 0 {
		return fail(17)
	}
	data := element("data", "")
	for _, h := range selected {
		value := h.Temperature
		switch p.Tag {
		case "Setpoint":
			value = h.Setpoint
		case "Defrost":
			value = float64(boolInt(h.Defrost))
		case "Compressor":
			value = float64(boolInt(h.Compressor))
		case "Door":
			value = float64(boolInt(h.Door))
		case "MainSwitch":
			return fail(16)
		}
		text := strconv.Itoa(int(value))
		if !p.Digital {
			text = numericTemperature(value, cmd.value("units"))
		}
		data.Children = append(data.Children, element("y", text))
	}
	out := response("read_history", 0)
	out.Attrs = append(out.Attrs, deviceAttrs(d.Node)...)
	out.Attrs = append(out.Attrs, attr("actual_sample_rate", strconv.Itoa(rate)))
	echoCommandAttrs(&out, cmd, "sample_rate", "units")
	out.Children = []xmlElement{children("starttime", dateFields(selected[0].Time)...)}
	if cmd.value("tag") != "" {
		out.Attrs = append(out.Attrs, attr("tag", p.Tag))
		out.Children = append(out.Children, element("display", p.Name))
	} else {
		out.Attrs = append(out.Attrs, attr("cid", strconv.Itoa(p.CID)), attr("vid", strconv.Itoa(p.VID)))
	}
	unit := "°C"
	if strings.ToUpper(cmd.value("units")) == "U" {
		unit = "°F"
	}
	if p.Digital {
		unit = ""
	}
	out.Children = append(out.Children, element("name", p.Name), data, element("unit", unit), element("digital", strconv.Itoa(boolInt(p.Digital))), element("timezone", "0"), element("daylightsavings", "0"), element("total_number", strconv.Itoa(len(selected))), element("actual_sample_rate", strconv.Itoa(rate)), children("stoptime", dateFields(selected[len(selected)-1].Time)...))
	return out, 0, false, d.Node
}

func echoCommandAttrs(out *xmlElement, cmd xmlElement, names ...string) {
	for _, name := range names {
		if value := cmd.value(name); value != "" {
			out.Attrs = append(out.Attrs, attr(name, value))
		}
	}
}

func alarmFormatsValid(cmd xmlElement) bool {
	date, clock := cmd.value("date_format"), cmd.value("time_format")
	return (date == "" || date == "0" || date == "2") && (clock == "" || clock == "0" || clock == "1")
}

func alarmDate(t time.Time, cmd xmlElement) string {
	if t.IsZero() {
		return ""
	}
	if cmd.value("date_format") == "2" {
		return t.UTC().Format("02/01/06")
	}
	return t.UTC().Format("01/02/06")
}

func alarmTime(t time.Time, cmd xmlElement) string {
	if t.IsZero() {
		return ""
	}
	if cmd.value("time_format") == "1" {
		return t.UTC().Format("15:04")
	}
	return t.UTC().Format("03:04PM")
}

func alarmEpoch(t time.Time) string {
	if t.IsZero() {
		return "0"
	}
	return strconv.FormatInt(t.Unix(), 10)
}

func (s *Server) alarmSummary(cmd xmlElement) (xmlElement, int, bool, int) {
	action := cmd.value("action")
	fail := func(code int) (xmlElement, int, bool, int) { return response(action, code), code, false, 0 }
	if !alarmFormatsValid(cmd) {
		return fail(3)
	}
	var from time.Time
	if raw := cmd.value("day"); raw != "" {
		day, err := strconv.ParseInt(raw, 10, 32)
		if err != nil || day < 0 {
			return fail(3)
		}
		if day > 0 {
			now := s.now()
			midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
			from = time.Unix(midnight.Unix()-(day-1)*86400, 0).UTC()
		}
	}
	node := 0
	out := response(action, 0)
	if action == "read_device_alarms" {
		d, code := s.requestDevice(cmd)
		if code != 0 {
			return fail(code)
		}
		node = d.Node
		out.Attrs = append(out.Attrs, deviceAttrs(node)...)
	}
	echoCommandAttrs(&out, cmd, "day", "date_format", "time_format")
	active, acked, cleared := element("active", ""), element("acked", ""), element("cleared", "")
	total := 0
	var oldest, newest, retainedOldest, retainedNewest *alarm
	older := func(a, b *alarm) bool {
		return b == nil || a.Occurred.Before(b.Occurred) || a.Occurred.Equal(b.Occurred) && a.Ref < b.Ref
	}
	newer := func(a, b *alarm) bool {
		return b == nil || a.Occurred.After(b.Occurred) || a.Occurred.Equal(b.Occurred) && a.Ref > b.Ref
	}
	for i := range s.plant.Alarms {
		a := &s.plant.Alarms[i]
		if node > 0 && a.Node != node {
			continue
		}
		if older(a, retainedOldest) {
			retainedOldest = a
		}
		if newer(a, retainedNewest) {
			retainedNewest = a
		}
		if !from.IsZero() && a.Occurred.Before(from) {
			continue
		}
		total++
		ref := element("ref", strconv.Itoa(a.Ref), attr("name", a.Name))
		if !a.Active {
			cleared.Children = append(cleared.Children, ref)
		} else if a.Acknowledged {
			acked.Children = append(acked.Children, ref)
		} else {
			active.Children = append(active.Children, ref)
		}
		if older(a, oldest) {
			oldest = a
		}
		if newer(a, newest) {
			newest = a
		}
	}
	active.Children = append(active.Children, element("total_active", strconv.Itoa(len(active.Children))))
	acked.Children = append(acked.Children, element("total_acked", strconv.Itoa(len(acked.Children))))
	cleared.Children = append(cleared.Children, element("total_cleared", strconv.Itoa(len(cleared.Children))))
	out.Children = []xmlElement{element("total", strconv.Itoa(total)), active, acked, cleared}
	if oldest == nil {
		oldest, newest = retainedOldest, retainedNewest
	}
	for _, endpoint := range []struct {
		name  string
		alarm *alarm
	}{{"oldest", oldest}, {"newest", newest}} {
		ref, when := "0", "0"
		if endpoint.alarm != nil {
			ref = strconv.Itoa(endpoint.alarm.Ref)
			when = alarmTime(endpoint.alarm.Occurred, cmd) + " " + alarmDate(endpoint.alarm.Occurred, cmd)
		}
		out.Children = append(out.Children, children(endpoint.name, element("time", when), element("ref", ref)))
	}
	return out, 0, false, node
}

func (s *Server) alarmDetail(cmd xmlElement) (xmlElement, int, bool, int) {
	fail := func(code int) (xmlElement, int, bool, int) { return response("alarm_detail", code), code, false, 0 }
	if !alarmFormatsValid(cmd) || cmd.value("expanded") != "" && cmd.value("expanded") != "1" && cmd.value("expanded") != "2" {
		return fail(3)
	}
	only := cmd.value("only")
	if only != "" && only != "any" && only != "active" && only != "cleared" && only != "acked" && only != "unacked" {
		return fail(3)
	}
	mode, pivot := "", 0
	for _, key := range []string{"current", "before", "after", "newest", "oldest"} {
		value := cmd.value(key)
		if value == "" {
			continue
		}
		if mode != "" {
			return fail(3)
		}
		mode = key
		if key == "newest" || key == "oldest" {
			if value != "true" {
				return fail(3)
			}
		} else {
			var err error
			pivot, err = strconv.Atoi(value)
			if err != nil || pivot < 1 || int64(pivot) > 2147483647 {
				return fail(12)
			}
		}
	}
	if mode == "" {
		return fail(12)
	}
	var chosen *alarm
	for i := range s.plant.Alarms {
		a := &s.plant.Alarms[i]
		if only == "active" && !a.Active || only == "cleared" && a.Active || only == "acked" && !a.Acknowledged || only == "unacked" && a.Acknowledged {
			continue
		}
		if mode == "current" && a.Ref != pivot || mode == "before" && a.Ref >= pivot || mode == "after" && a.Ref <= pivot {
			continue
		}
		take := chosen == nil
		if chosen != nil {
			switch mode {
			case "newest":
				take = a.Occurred.After(chosen.Occurred) || a.Occurred.Equal(chosen.Occurred) && a.Ref > chosen.Ref
			case "oldest":
				take = a.Occurred.Before(chosen.Occurred) || a.Occurred.Equal(chosen.Occurred) && a.Ref < chosen.Ref
			case "before":
				take = a.Ref > chosen.Ref
			case "after":
				take = a.Ref < chosen.Ref
			}
		}
		if take {
			chosen = a
		}
	}
	if chosen == nil {
		return fail(12)
	}
	a := chosen
	d := s.plant.find(a.Node)
	out := response("alarm_detail", 0)
	echoCommandAttrs(&out, cmd, "only", "current", "before", "after", "newest", "oldest", "expanded", "date_format", "time_format", "units")
	status, ack := "cleared", "No"
	if a.Active {
		status = "active"
	}
	if a.Acknowledged {
		ack = "Yes"
	}
	out.Children = []xmlElement{element("ref", strconv.Itoa(a.Ref)), element("addr", strconv.Itoa(a.Node)), element("deviceName", d.Name), element("unitNumber", "1"), element("unitName", s.plant.Identity.UnitName), element("name", a.Name), element("status", status), element("action", "Critical"), element("clearable", strconv.Itoa(boolInt(!a.Active))), element("acknowledgement", ack), element("occurDate", alarmDate(a.Occurred, cmd)), element("occurTime", alarmTime(a.Occurred, cmd)), element("epoch", alarmEpoch(a.Occurred)), element("clearDate", alarmDate(a.Cleared, cmd)), element("clearTime", alarmTime(a.Cleared, cmd)), element("epoch_cleared", alarmEpoch(a.Cleared)), element("device_id", "084B8020_015B"), element("ref_tag_id", "AirTemperature")}
	if cmd.value("expanded") == "2" {
		setting := "Air temperature above cutout by 3 °C"
		if strings.EqualFold(cmd.value("units"), "U") {
			setting = "Air temperature above cutout by 5.4 °F"
		}
		out.Children = append(out.Children, element("storeName", s.plant.Identity.StoreName), element("deviceModel", "AK-CC550-B-015B"), element("nodetype", "16"), element("class", "Refrigeration"), element("value", "Trip"), element("setting", setting))
	}
	return out, 0, false, a.Node
}
