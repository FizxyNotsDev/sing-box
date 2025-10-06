package rule

import (
	"strings"

	"github.com/sagernet/sing-box/adapter"
)

var _ RuleItem = (*DomainKeywordItem)(nil)

type DomainKeywordItem struct {
	keywords []string
}

func NewDomainKeywordItem(keywords []string) *DomainKeywordItem {
	return &DomainKeywordItem{keywords}
}

func (r *DomainKeywordItem) Match(metadata *adapter.InboundContext) bool {
	domains := make([]string, 0, 3)
	if metadata.Destination.IsFqdn() {
		domains = append(domains, strings.ToLower(metadata.Destination.Fqdn))
	}
	if metadata.SniffHost != "" {
		domains = append(domains, strings.ToLower(metadata.SniffHost))
	}
	if metadata.Domain != "" {
		domains = append(domains, strings.ToLower(metadata.Domain))
	}
	if len(domains) == 0 {
		return false
	}
	for _, domainHost := range domains {
		for _, keyword := range r.keywords {
			if strings.Contains(domainHost, keyword) {
				return true
			}
		}
	}
	return false
}

func (r *DomainKeywordItem) String() string {
	kLen := len(r.keywords)
	if kLen == 1 {
		return "domain_keyword=" + r.keywords[0]
	} else if kLen > 3 {
		return "domain_keyword=[" + strings.Join(r.keywords[:3], " ") + "...]"
	} else {
		return "domain_keyword=[" + strings.Join(r.keywords, " ") + "]"
	}
}
