package gohpts

import (
	"bufio"
	"bytes"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/shadowy-pycoder/colors"
	"github.com/shadowy-pycoder/mshark/layers"
)

var (
	ipPortPattern = regexp.MustCompile(
		`(?:(?:\[(?:[0-9a-fA-F:.]+(?:%[a-zA-Z0-9_.-]+)?)\]|(?:\d{1,3}\.){3}\d{1,3})(?::(6553[0-5]|655[0-2]\d|65[0-4]\d{2}|6[0-4]\d{3}|[1-5]?\d{1,4}))?|(?:[0-9a-fA-F:]+:+[0-9a-fA-F:]+(?:%[a-zA-Z0-9_.-]+)?))`,
	)
	domainPattern = regexp.MustCompile(
		`\b(?:[a-zA-Z0-9-]{1,63}\.)+(?:com|net|org|io|co|uk|ru|de|edu|gov|info|biz|dev|app|ai|tv|local)(?::(6553[0-5]|655[0-2]\d|65[0-4]\d{2}|6[0-4]\d{3}|[1-5]?\d{1,4}))?\b`,
	)
	jwtPattern  = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)
	authPattern = regexp.MustCompile(
		`(?i)(?:"|')?(authorization|auth[_-]?token|access[_-]?token|api[_-]?key|secret|token)(?:"|')?\s*[:=]\s*(?:"|')?([^\s"'&]+)`,
	)
	credsPattern = regexp.MustCompile(
		`(?i)(?:"|')?(username|user|login|email|password|pass|pwd)(?:"|')?\s*[:=]\s*(?:"|')?([^\s"'&]+)`,
	)
	macPattern = regexp.MustCompile(
		`(?i)(?:\b[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}\b|\b[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}\b|\b[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}\b|\b[a-z0-9_]+_[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}\b)`,
	)
	portsPattern = regexp.MustCompile(
		`^\s*(?:6553[0-5]|655[0-2]\d|65[0-4]\d{2}|6[0-4]\d{3}|[1-5]\d{0,4}|[1-9]\d{0,3})\s*(?:,\s*(?:6553[0-5]|655[0-2]\d|65[0-4]\d{2}|6[0-4]\d{3}|[1-5]\d{0,4}|[1-9]\d{0,3})\s*)*$`,
	)
)

var rColors = []func(string) *colors.Color{
	colors.Beige,
	colors.Blue,
	colors.Gray,
	colors.Green,
	colors.LightBlue,
	colors.Magenta,
	colors.Red,
	colors.Yellow,
	colors.BeigeBg,
	colors.BlueBg,
	colors.GrayBg,
	colors.GreenBg,
	colors.LightBlueBg,
	colors.MagentaBg,
	colors.RedBgDark,
	colors.YellowBg,
	colors.NewColor(215),
	colors.NewColorBgDark(215),
	colors.NewColor(138),
	colors.NewColorBgDark(138),
}

func randColor() func(string) *colors.Color {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	randIndex := r.Intn(len(rColors))
	return rColors[randIndex]
}

func getID(nocolor bool) string {
	id := uuid.New()
	if nocolor {
		return colors.WrapBrackets(id.String())
	}
	return randColor()(colors.WrapBrackets(id.String())).String()
}

func colorizeStatus(code int, status string, bg bool) string {
	if bg {
		if code < 300 {
			status = colors.GreenBg(status).String()
		} else if code < 400 {
			status = colors.YellowBg(status).String()
		} else {
			status = colors.RedBgDark(status).String()
		}
	} else {
		if code < 300 {
			status = colors.Green(status).String()
		} else if code < 400 {
			status = colors.Yellow(status).String()
		} else {
			status = colors.Red(status).String()
		}
	}
	return status
}

func colorizeHTTP(
	req *http.Request,
	resp *http.Response,
	reqBodySaved, respBodySaved *[]byte,
	id string,
	ts,
	body,
	nocolor bool,
) string {
	var sb strings.Builder
	if ts {
		fmt.Fprintf(&sb, "%s ", colorizeTimestamp(time.Now(), nocolor))
	}
	if nocolor {
		sb.WriteString(id)
		fmt.Fprintf(&sb, " %s %s %s ", req.Method, req.URL, req.Proto)
		if req.UserAgent() != "" {
			sb.WriteString(colors.WrapBrackets(req.UserAgent()))
		}
		if req.ContentLength > 0 {
			fmt.Fprintf(&sb, " Len: %d", req.ContentLength)
		}
		sb.WriteString(" -> ")
		fmt.Fprintf(&sb, "%s %s ", resp.Proto, resp.Status)
		if resp.ContentLength > 0 {
			fmt.Fprintf(&sb, "Len: %d", resp.ContentLength)
		}
		if body && len(*reqBodySaved) > 0 {
			b := colorizeBody(reqBodySaved, nocolor)
			if b != "" {
				sb.WriteString("\n")
				fmt.Fprintf(&sb, "%s ", colorizeTimestamp(time.Now(), nocolor))
				sb.WriteString(id)
				fmt.Fprintf(&sb, " req_body: %s", b)
			}
		}
		if body && len(*respBodySaved) > 0 {
			b := colorizeBody(respBodySaved, nocolor)
			if b != "" {
				sb.WriteString("\n")
				fmt.Fprintf(&sb, "%s ", colorizeTimestamp(time.Now(), nocolor))
				sb.WriteString(id)
				fmt.Fprintf(&sb, " resp_body: %s", b)
			}
		}
	} else {
		sb.WriteString(id)
		sb.WriteString(colors.Gray(fmt.Sprintf(" %s ", req.Method)).String())
		sb.WriteString(colors.YellowBg(fmt.Sprintf("%s ", req.URL)).String())
		sb.WriteString(colors.BlueBg(fmt.Sprintf("%s ", req.Proto)).String())
		if req.UserAgent() != "" {
			sb.WriteString(colors.Gray(colors.WrapBrackets(req.UserAgent())).String())
		}
		if req.ContentLength > 0 {
			sb.WriteString(colors.BeigeBg(fmt.Sprintf(" Len: %d", req.ContentLength)).String())
		}
		sb.WriteString(colors.MagentaBg(" →  ").String())
		sb.WriteString(colors.BlueBg(fmt.Sprintf("%s ", resp.Proto)).String())
		sb.WriteString(colorizeStatus(resp.StatusCode, fmt.Sprintf("%s ", resp.Status), true))
		if resp.ContentLength > 0 {
			sb.WriteString(colors.BeigeBg(fmt.Sprintf("Len: %d", resp.ContentLength)).String())
		}
		if body && len(*reqBodySaved) > 0 {
			b := colorizeBody(reqBodySaved, nocolor)
			if b != "" {
				sb.WriteString("\033[K\n")
				fmt.Fprintf(&sb, "%s ", colorizeTimestamp(time.Now(), nocolor))
				sb.WriteString(id)
				sb.WriteString(colors.RedBgDark(" req_body: ").String())
				sb.WriteString(b)
			}
		}
		if body && len(*respBodySaved) > 0 {
			b := colorizeBody(respBodySaved, nocolor)
			if b != "" {
				sb.WriteString("\033[K\n")
				fmt.Fprintf(&sb, "%s ", colorizeTimestamp(time.Now(), nocolor))
				sb.WriteString(id)
				sb.WriteString(colors.RedBgDark(" resp_body: ").String())
				sb.WriteString(b)
			}
		}
		sb.WriteString("\033[K")
	}
	return sb.String()
}

func colorizeTLS(req *layers.TLSClientHello, resp *layers.TLSServerHello, id string, nocolor bool) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s ", colorizeTimestamp(time.Now(), nocolor))
	sb.WriteString(id)
	if nocolor {
		fmt.Fprintf(&sb, " %s ", req.TypeDesc)
		if req.Length > 0 {
			fmt.Fprintf(&sb, " Len: %d", req.Length)
		}
		if req.ServerName != nil && req.ServerName.SNName != "" {
			fmt.Fprintf(&sb, " SNI: %s", req.ServerName.SNName)
		}
		if req.Version != nil && req.Version.Desc != "" {
			fmt.Fprintf(&sb, " Ver: %s", req.Version.Desc)
		}
		if req.ALPN != nil {
			fmt.Fprintf(&sb, " ALPN: %v", req.ALPN)
		}
		sb.WriteString(" -> ")
		sb.WriteString("\n")
		fmt.Fprintf(&sb, "%s ", colorizeTimestamp(time.Now(), nocolor))
		sb.WriteString(id)
		fmt.Fprintf(&sb, " %s ", resp.TypeDesc)
		if resp.Length > 0 {
			fmt.Fprintf(&sb, " Len: %d", resp.Length)
		}
		if resp.SessionID != "" {
			fmt.Fprintf(&sb, " SID: %s", resp.SessionID)
		}
		if resp.CipherSuite != nil && resp.CipherSuite.Desc != "" {
			fmt.Fprintf(&sb, " CS: %s", resp.CipherSuite.Desc)
		}
		if resp.SupportedVersion != nil && resp.SupportedVersion.Desc != "" {
			fmt.Fprintf(&sb, " Ver: %s", resp.SupportedVersion.Desc)
		}
		if resp.ExtensionLength > 0 {
			fmt.Fprintf(&sb, " ExtLen: %d", resp.ExtensionLength)
		}
	} else {
		sb.WriteString(colors.Magenta(fmt.Sprintf(" %s ", req.TypeDesc)).Bold())
		if req.Length > 0 {
			sb.WriteString(colors.BeigeBg(fmt.Sprintf(" Len: %d", req.Length)).String())
		}
		if req.ServerName != nil && req.ServerName.SNName != "" {
			sb.WriteString(colors.YellowBg(fmt.Sprintf(" SNI: %s", req.ServerName.SNName)).String())
		}
		if req.Version != nil && req.Version.Desc != "" {
			sb.WriteString(colors.GreenBg(fmt.Sprintf(" Ver: %s", req.Version.Desc)).String())
		}
		if req.ALPN != nil {
			sb.WriteString(colors.BlueBg(fmt.Sprintf(" ALPN: %v", req.ALPN)).String())
		}
		sb.WriteString(colors.MagentaBg(" →  ").String())
		sb.WriteString("\033[K\n")
		fmt.Fprintf(&sb, "%s ", colorizeTimestamp(time.Now(), nocolor))
		sb.WriteString(id)
		sb.WriteString(colors.LightBlue(fmt.Sprintf(" %s ", resp.TypeDesc)).Bold())
		if resp.Length > 0 {
			sb.WriteString(colors.BeigeBg(fmt.Sprintf(" Len: %d", resp.Length)).String())
		}
		if resp.SessionID != "" {
			sb.WriteString(colors.Gray(fmt.Sprintf(" SID: %s", resp.SessionID)).String())
		}
		if resp.CipherSuite != nil && resp.CipherSuite.Desc != "" {
			sb.WriteString(colors.Yellow(fmt.Sprintf(" CS: %s", resp.CipherSuite.Desc)).Bold())
		}
		if resp.SupportedVersion != nil && resp.SupportedVersion.Desc != "" {
			sb.WriteString(colors.GreenBg(fmt.Sprintf(" Ver: %s", resp.SupportedVersion.Desc)).String())
		}
		if resp.ExtensionLength > 0 {
			sb.WriteString(colors.BeigeBg(fmt.Sprintf(" ExtLen: %d", resp.ExtensionLength)).String())
		}
		sb.WriteString("\033[K")
	}
	return sb.String()
}

func colorizeRData(rec *layers.ResourceRecord) string {
	var rdata string
	switch rd := rec.RData.(type) {
	case *layers.RDataA:
	case *layers.RDataAAAA:
		rdata = fmt.Sprintf("%s %s ", colors.LightBlue(rec.Type.Name), colors.Gray(rd.Address.String()))
	case *layers.RDataNS:
		rdata = fmt.Sprintf("%s %s ", colors.LightBlue(rec.Type.Name), colors.Gray(rd.NsdName))
	case *layers.RDataCNAME:
		rdata = fmt.Sprintf("%s %s ", colors.LightBlue(rec.Type.Name), colors.Gray(rd.CName))
	case *layers.RDataSOA:
		rdata = fmt.Sprintf("%s %s ", colors.LightBlue(rec.Type.Name), colors.Gray(rd.PrimaryNS))
	case *layers.RDataMX:
		rdata = fmt.Sprintf("%s %s %s ", colors.LightBlue(rec.Type.Name), colors.Gray(fmt.Sprintf("%d", rd.Preference)), colors.Gray(rd.Exchange))
	case *layers.RDataTXT:
		rdata = fmt.Sprintf("%s %s ", colors.LightBlue(rec.Type.Name), colors.Gray(rd.TxtData))
	default:
		rdata = fmt.Sprintf("%s ", colors.LightBlue(rec.Type.Name))
	}
	return rdata
}

func colorizeDNS(req, resp *layers.DNSMessage, id string, nocolor bool) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s ", colorizeTimestamp(time.Now(), nocolor))
	sb.WriteString(id)
	if nocolor {
		fmt.Fprintf(&sb, " DNS %s (%s) %#04x ", req.Flags.OPCode.Desc, req.Flags.QR.Desc, req.TransactionID)
		for _, rec := range req.Questions {
			fmt.Fprintf(&sb, "%s %s ", rec.Type.Name, rec.Name)
		}
		for _, rec := range req.AnswerRRs {
			sb.WriteString(rec.Summary())
		}
		for _, rec := range req.AuthorityRRs {
			sb.WriteString(rec.Summary())
		}
		for _, rec := range req.AdditionalRRs {
			sb.WriteString(rec.Summary())
		}
		sb.WriteString("\n")
		fmt.Fprintf(&sb, "%s ", colorizeTimestamp(time.Now(), nocolor))
		sb.WriteString(id)

		fmt.Fprintf(&sb, " DNS %s (%s) %s %#04x ", resp.Flags.OPCode.Desc, resp.Flags.QR.Desc, resp.Flags.RCode.Desc, resp.TransactionID)
		for _, rec := range resp.Questions {
			fmt.Fprintf(&sb, "%s %s ", rec.Type.Name, rec.Name)
		}
		for _, rec := range resp.AnswerRRs {
			sb.WriteString(rec.Summary())
		}
		for _, rec := range resp.AuthorityRRs {
			sb.WriteString(rec.Summary())
		}
		for _, rec := range resp.AdditionalRRs {
			sb.WriteString(rec.Summary())
		}
	} else {
		sb.WriteString(colors.Gray(fmt.Sprintf(" DNS %s (%s)", req.Flags.OPCode.Desc, req.Flags.QR.Desc)).Bold())
		sb.WriteString(colors.Beige(fmt.Sprintf(" %#04x ", req.TransactionID)).String())
		for _, rec := range req.Questions {
			fmt.Fprintf(&sb, "%s %s ", colors.LightBlue(rec.Type.Name), colors.Gray(rec.Name))
		}
		for _, rec := range req.AnswerRRs {
			sb.WriteString(colorizeRData(rec))
		}
		for _, rec := range req.AuthorityRRs {
			sb.WriteString(colorizeRData(rec))
		}
		for _, rec := range req.AdditionalRRs {
			sb.WriteString(colorizeRData(rec))
		}
		sb.WriteString("\033[K\n")
		fmt.Fprintf(&sb, "%s ", colorizeTimestamp(time.Now(), nocolor))
		sb.WriteString(id)
		sb.WriteString(colors.Blue(fmt.Sprintf(" DNS %s (%s)", resp.Flags.OPCode.Desc, resp.Flags.QR.Desc)).Bold())
		sb.WriteString(colors.Gray(fmt.Sprintf(" %s", resp.Flags.RCode.Desc)).String())
		sb.WriteString(colors.Beige(fmt.Sprintf(" %#04x ", resp.TransactionID)).String())
		for _, rec := range resp.Questions {
			fmt.Fprintf(&sb, "%s %s ", colors.LightBlue(rec.Type.Name), colors.Gray(rec.Name))
		}
		for _, rec := range resp.AnswerRRs {
			sb.WriteString(colorizeRData(rec))
		}
		for _, rec := range resp.AuthorityRRs {
			sb.WriteString(colorizeRData(rec))
		}
		for _, rec := range resp.AdditionalRRs {
			sb.WriteString(colorizeRData(rec))
		}
		sb.WriteString("\033[K")
	}
	return sb.String()
}

func highlightPatterns(line string, nocolor bool) (string, bool) {
	matched := false

	// TODO: make this configurable
	// TODO: write cred matches to separate file
	// line, matched = replace(line, ipPortPattern, colors.YellowBg, matched, nocolor)
	// line, matched = replace(line, domainPattern, colors.YellowBg, matched, nocolor)
	line, matched = replace(line, jwtPattern, colors.Magenta, matched, nocolor)
	line, matched = replace(line, authPattern, colors.Magenta, matched, nocolor)
	line, matched = replace(line, credsPattern, colors.GreenBg, matched, nocolor)

	return line, matched
}

func replace(line string, re *regexp.Regexp, color func(string) *colors.Color, matched, nocolor bool) (string, bool) {
	if re.MatchString(line) {
		matched = true
		if !nocolor {
			line = re.ReplaceAllStringFunc(line, func(s string) string {
				return color(s).String()
			})
		}
	}
	return line, matched
}

func colorizeBody(b *[]byte, nocolor bool) string {
	matches := make([]string, 0, 3)
	scanner := bufio.NewScanner(bytes.NewReader(*b))
	for scanner.Scan() {
		line := scanner.Text()
		if highlighted, ok := highlightPatterns(line, nocolor); ok {
			matches = append(matches, strings.Trim(highlighted, "\r\n\t "))
		}
	}
	return strings.Join(matches, "\n")
}

func colorizeTimestamp(ts time.Time, nocolor bool) string {
	if nocolor {
		return colors.WrapBrackets(ts.Format(time.TimeOnly))
	}
	return colors.Gray(colors.WrapBrackets(ts.Format(time.TimeOnly))).String()
}

func colorizeLogMessage(line string, nocolor bool) string {
	if nocolor {
		return line
	}
	result := ipPortPattern.ReplaceAllStringFunc(line, func(match string) string {
		if macPattern.MatchString(match) {
			return match
		}
		return colors.Gray(match).String()
	})
	result = domainPattern.ReplaceAllStringFunc(result, func(match string) string {
		return colors.Yellow(match).String()
	})
	result = macPattern.ReplaceAllStringFunc(result, func(match string) string {
		return colors.Yellow(match).String()
	})
	return result
}

func colorizeErrMessage(line string, nocolor bool) string {
	if nocolor {
		return line
	}
	result := ipPortPattern.ReplaceAllStringFunc(line, func(match string) string {
		if macPattern.MatchString(match) {
			return match
		}
		return colors.Red(match).String()
	})
	result = domainPattern.ReplaceAllStringFunc(result, func(match string) string {
		return colors.Red(match).String()
	})
	result = strings.ReplaceAll(result, "->", "→ ")
	return result
}

func colorizeChainType(chainType string, nocolor bool) string {
	if nocolor {
		return colors.WrapBrackets(chainType)
	}
	return colors.WrapBrackets(colors.LightBlueBg(chainType).String())
}

func colorizeConnections(srcRemote, srcLocal, dstRemote, dstLocal net.Addr, id string, r *http.Request, nocolor bool) string {
	var sb strings.Builder
	if nocolor {
		sb.WriteString(id)
		fmt.Fprintf(
			&sb,
			" Src: %s->%s -> Dst: %s->%s",
			srcRemote,
			srcLocal,
			dstLocal,
			dstRemote,
		)
		sb.WriteString("\n")
		fmt.Fprintf(&sb, "%s ", colorizeTimestamp(time.Now(), nocolor))
		sb.WriteString(id)
		fmt.Fprintf(&sb, " %s %s %s ", r.Method, r.Host, r.Proto)
	} else {
		sb.WriteString(id)
		sb.WriteString(colors.Green(fmt.Sprintf(" Src: %s→ %s", srcRemote, srcLocal)).String())
		sb.WriteString(colors.Magenta(" →  ").String())
		sb.WriteString(colors.Blue(fmt.Sprintf("Dst: %s→ %s", dstLocal, dstRemote)).String())
		sb.WriteString("\033[K\n")
		fmt.Fprintf(&sb, "%s ", colorizeTimestamp(time.Now(), nocolor))
		sb.WriteString(id)
		sb.WriteString(colors.Gray(fmt.Sprintf(" %s ", r.Method)).String())
		sb.WriteString(colors.YellowBg(fmt.Sprintf("%s ", r.Host)).String())
		sb.WriteString(colors.BlueBg(fmt.Sprintf("%s ", r.Proto)).String())
		sb.WriteString("\033[K")
	}
	return sb.String()
}

func colorizeConnectionsTransparent(
	srcRemote, srcLocal, dstLocal, dstRemote net.Addr,
	dst,
	id string,
	nocolor bool,
) string {
	var sb strings.Builder
	if nocolor {
		sb.WriteString(id)
		fmt.Fprintf(
			&sb, " Src: %s->%s -> Dst: %s->%s Orig Dst: %s",
			srcRemote,
			srcLocal,
			dstLocal,
			dstRemote,
			dst,
		)
	} else {
		sb.WriteString(id)
		sb.WriteString(colors.Green(fmt.Sprintf(" Src: %s→ %s", srcRemote, srcLocal)).String())
		sb.WriteString(colors.Magenta(" →  ").String())
		sb.WriteString(colors.Blue(fmt.Sprintf("Dst: %s→ %s ", dstLocal, dstRemote)).String())
		sb.WriteString(colors.BeigeBg(fmt.Sprintf("Orig Dst: %s", dst)).String())
		sb.WriteString("\033[K")
	}
	return sb.String()
}
