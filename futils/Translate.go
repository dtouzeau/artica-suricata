package futils

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/leeqvip/gophp"
)

var langFileRegex = regexp.MustCompile(`"en-[a-z]+`)

func Translate(data string, lang string) string {

	lang = strings.ToLower(lang)
	if RegexFind(langFileRegex, lang) {
		lang = "en"
	}
	ArrayCompiled := make(map[string]string)
	Language_file := "/usr/share/artica-postfix/ressources/language/" + lang + ".db"
	if !FileExists(Language_file) {
		Language_file = "/usr/share/artica-postfix/ressources/language/en.db"
	}
	langdata := FileGetContents(Language_file)
	langArray, _ := gophp.Unserialize([]byte(langdata))

	if rec, ok := langArray.(map[string]interface{}); ok {
		for key, val := range rec {
			ArrayCompiled[key] = fmt.Sprintf("%v", val)
		}
	}

	re := regexp.MustCompile(`\{(.+?)\}`)
	matches := re.FindAllStringSubmatch(data, -1)
	for _, match := range matches { // match is a type of []byte

		PatternMatches := match[0]
		if _translate_dustbin(PatternMatches) {
			continue
		}
		Token := Trim(match[1])
		if len(Token) == 0 {
			continue
		}
		DataToReplace := ArrayCompiled[Token]
		if len(DataToReplace) == 0 {
			continue
		}
		DataToReplace = ReplaceSpecialsCharacters(DataToReplace)
		data = strings.ReplaceAll(data, PatternMatches, DataToReplace)
	}

	return data
}

func ReplaceSpecialsCharacters(data string) string {
	data = strings.ReplaceAll(data, "\"", "&quot;")
	data = strings.ReplaceAll(data, "%C3%89", "&Eacute;")
	data = strings.ReplaceAll(data, "%C3§", "&ccedil;")
	data = strings.ReplaceAll(data, "%C3§", "&ccedil;")
	data = strings.ReplaceAll(data, "â%80%99", "`")
	data = strings.ReplaceAll(data, "%C3£", "&atilde;")
	data = strings.ReplaceAll(data, "%C3¡", "&aacute;")
	data = strings.ReplaceAll(data, "%C3%B3", "&oacute;")
	data = strings.ReplaceAll(data, "%C3%AD", "&iacute;")
	data = strings.ReplaceAll(data, "%C3µ", "&otilde;")
	data = strings.ReplaceAll(data, "%C3%BA", "&uacute;")
	data = strings.ReplaceAll(data, "%C3%8A", "&Ecirc;")
	data = strings.ReplaceAll(data, "%C3%9A", "&uacute;")
	data = strings.ReplaceAll(data, "%C3%B1", "&ntilde;")
	data = strings.ReplaceAll(data, "%C2%BF", "&iquest;")
	data = strings.ReplaceAll(data, "%C3%C2¡", "&aacute;")
	data = strings.ReplaceAll(data, "%C3%A4", "&auml;")
	data = strings.ReplaceAll(data, "%C3%BC", "&uuml;")
	data = strings.ReplaceAll(data, "%C3%B6", "&ouml;")
	data = strings.ReplaceAll(data, "%C3%9F", "&szlig;")
	data = strings.ReplaceAll(data, "%C3%8D", "&iacute;")
	data = strings.ReplaceAll(data, "%C3%84", "&Auml;")
	data = strings.ReplaceAll(data, "%C3%9C", "&Uuml;")
	data = strings.ReplaceAll(data, "%C3%AC", "&igrave;")
	data = strings.ReplaceAll(data, "%C5%BC", "&#x142;")
	data = strings.ReplaceAll(data, "%C5%82", "&#x17C;")
	data = strings.ReplaceAll(data, "%C4%87", "&#x107;")
	data = strings.ReplaceAll(data, "%C5%BA", "&#x17A;")
	data = strings.ReplaceAll(data, "%C5%9A", "&#x15A;")
	data = strings.ReplaceAll(data, "%C4%99", "&#x119;")
	data = strings.ReplaceAll(data, "%C4%85", "&#x105;")
	data = strings.ReplaceAll(data, "%C5%84", "&#x144;")
	data = strings.ReplaceAll(data, "%C5%9B", "&#x15B;")
	data = strings.ReplaceAll(data, "%C5%B9", "&#x179;")
	data = strings.ReplaceAll(data, "%u0142", "&#x142;")
	data = strings.ReplaceAll(data, "%u0105", "&#x105;")
	data = strings.ReplaceAll(data, "%u0107", "&#x107;")
	data = strings.ReplaceAll(data, "%u017C", "&#x17C;")
	data = strings.ReplaceAll(data, "%u0119", "&#x119;")
	data = strings.ReplaceAll(data, "\\'", "'")
	data = strings.ReplaceAll(data, "[br]]", "<br>")
	data = strings.ReplaceAll(data, "[br]", "<br>")
	data = strings.ReplaceAll(data, "[BR]", "<br>")
	data = strings.ReplaceAll(data, "[b]", "<strong>")
	data = strings.ReplaceAll(data, "[/b]", "</strong>")
	data = strings.ReplaceAll(data, "[B]", "<strong>")
	data = strings.ReplaceAll(data, "[/B]", "</strong>")
	return data
}
func _translate_dustbin(str string) bool {

	str = Trim(str)
	if len(str) == 0 {
		return (true)
	}

	if strings.Contains(str, "font-size:") {
		return true
	}
	if strings.Contains(str, "float:") {
		return true
	}
	if strings.Contains(str, "content:") {
		return true
	}
	if strings.Contains(str, "margin-right:") {
		return true
	}
	return false
}
