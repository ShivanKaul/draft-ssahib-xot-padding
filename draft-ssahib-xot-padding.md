---
title: Padding Considerations for DNS Zone Transfers-over-TLS
abbrev: Padding Considerations for XoT
docname: draft-ssahib-xot-padding
category: info

ipr: trust200902
area: General
workgroup: dprive
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
    -
        ins: S. Sahib
        name: Shivan Sahib
        organization: Salesforce.com
        email: ssahib@salesforce.com
    -
        ins: H. Zhang
        name: Han Zhang
        organization: Salesforce.com
        email: hzhang@salesforce.com
    -
        ins: S. Dickinson
        name: Sara Dickinson
        organization: Sinodun IT
        email: sara@sinodun.com


normative:
  RFC2119:

  I-D.draft-ietf-dprive-xfr-over-tls:
    title: "DNS Zone Transfer-over-TLS"
    date: 2020
    author:
      - ins: W. Toorop
      - ins: S. Dickinson
      - ins: S. Sahib
      - ins: P. Aras
      - ins: A. Mankin
    target: https://datatracker.ietf.org/doc/draft-ietf-dprive-xfr-over-tls

informative:



--- abstract

{{I-D.draft-ietf-dprive-xfr-over-tls}} specifies use of TLS to prevent zone content collection via passive monitoring of zone transfers. This document lists considerations for various padding policies and provides recommendations.

--- middle

# Introduction

It's not uncommon that in some companyies, each of their customers is given a subdomain under the customers' domains. In this case, if the attackers capture the AXoT traffic, they can estimate the number of customers in these companies. Similarly, when a company has a new customer, a subdomain will be created. If the attackers capture the encrypted IXoT traffic, they can estimate the number of new domains included in IXoT. After collecting IXoT for a period of time and doing some analysis, the attackers can even extract more business information, for example, whether the company is getting more bussiness than the past mont or it is losing their business.

In this draft, we introduce the padding for AXoT and IXoT to i) to obfuscate the actual size of the transferred zone to minimize information leakage about the entire contents of the zone. and 2) to obfuscate the incremental changes to the zone between SOA updates to minimize information leakage about zone update activity and growth.

# Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 {{RFC2119}} {{!RFC8174}}
when, and only when, they appear in all capitals, as shown here.

# Threat Model
In the thread models, we assume the attackers are interested in a single zone, but the thread models can be generalized to any number of zones. 

## A primary server hosts multiple zones and persistent tcp connection is used 
If a primary server hosts multiple zones and persistent tcp connection is used for AXoT and IXoT of these zones, then the attackers can not tell the the length of AXoT nor IXoT responses for the zone to attack, because the attackers only see the encrypted streams and they cannot differentiate the streams for different zones.

## A primary server hosts multiple zones and persistent tcp connection is not used 
If a primary server hosts multiple zones but persistent tcp connection is not used for AXoT and IXoT of these zones, then each AXoT and IXoT will be transfered in a new connections. When attackers see streams between the primary and secondary, it is not obvious which zone is being transfered because the primary hosts multiple zones. However, the attackers can query the SOA records for all the zones, and correlate the serial numbers with the size of streams, then they might be able to find out the zone.

## A primary server hosts a single zone
Attackers can get the length of AXoT and IXoT responses for the zone to attack.


# Padding for AXoT

As mentioned in {{I-D.draft-ietf-dprive-xfr-over-tls}}, the goal of padding AXoT responses would be two fold:

- to obfuscate the actual size of the transferred zone to minimize information leakage about the entire contents of the zone.
- to obfuscate the incremental changes to the zone between SOA updates to minimize information leakage about zone update activity and growth.



A simplistic option, following the premise of the Block-Length Padding strategy recommended in [RFC8467], would be to specify

a 'message size' to which each individual AXFR response would always be padded (with a maximum value of 65353 bytes) and
a compatible 'zone block size' for a zone to which the sum total of all the AXFR responses should be padded. This could equivalently be specified as a 'zone number of AXFR responses block size'.
Primary implementations SHOULD provide a configurable block-size based padding mechanism.

This second requirement is likely to require an implementation to create 'empty' AXFR responses in order to pad a zone to the zone block size. That is, AXFR responses that contain no RRs apart from the EDNS(0) option for padding. However, as will existing AXFR, the last message sent MUST contain the same SOA that was in the first message of the AXFR response series in order to signal the conclusion of the zone transfer.

[RFC5936] says:

"Each AXFR response message SHOULD contain a sufficient number of RRs
to reasonably amortize the per-message overhead, up to the largest
number that will fit within a DNS message (taking the required
content of the other sections into account, as described below)."
'Empty' AXoT responses generated in order to meet a padding requirement are exempt from the above statement. Secondary implementations MUST be resilient to receiving padded AXFR responses including 'empty' AXFR response that contain only padding.

Observation of the zone transfers would then reveal only zone block size step changes in the total zone size (if the zone size changed sufficiently) obfuscating the smaller fluctuations.

Choosing a message size of less than 65535 only really makes sense for small zones that can be transferred in a single response (in which case the zone block size can be set to the same value). Choosing a zone block size close to the current zone size would provide some protection with a minimal overhead. Choosing a zone block size much larger than the current zone size would provide increased protection but with increased overhead.

As with any padding strategy the trade-off between increased bandwidth and processing due to the larger size and number of padded DNS messages and the corresponding gain in confidentiality must be carefully considered.

As noted in [RFC8467], the maximum message length, as dictated by the protocol, limits the space for EDNS(0) options. Since padding will reduce the message space available to other EDNS(0) options, the "Padding" option MUST be the last EDNS(0) option applied before a DNS message is sent. In particular for AXFR, that means that if the message is to be signed with, e.g., TSIG this must be done before the padding is applied.



# Padding for IXoT

As mentioned in {{I-D.draft-ietf-dprive-xfr-over-tls}}, the goal of padding IXoT responses is to minimize leakage about zone update activity through the size and timing of responses.

The frequency of IXFR is affected by if and how the zone is DNSSEC signed. For example, both the following zones might see frequent similarly sized IXFR exchanges

* a small DNSSEC signed zone with frequent record updates
* a large DNSSEC signed zone that receives no updates but the RRSIG signature
  expiry dates are jittered across the signature lifetime window

A simplistic option, following the premise of the Block-Length Padding strategy
recommended in [@RFC8467], would be to specify

* a 'message block size' where each individual IXFR response would always be
  padded to the closest multiple of that number of bytes (with a maximum value
  of 65353 bytes)

Choosing a message block size of less than 65535 will expose some information about zone activity but obfuscate the more granular changes.

As with any padding strategy the trade-off between increased bandwidth and processing due to the larger size and number of padded DNS messages and the corresponding gain in confidentiality must be carefully considered. For IXFR a detailed understanding of the zone contents and transfer pattern is likely to be required in order to select the optimal block size for a zone.

Primary implementations SHOULD provide a configurable message block size based padding mechanism. As noted in [@RFC8467], the maximum message length, as dictated by the protocol,
limits the space for EDNS(0) options. Since padding will reduce the message space available to other EDNS(0) options, the "Padding" option MUST be the last EDNS(0) option applied before a DNS message is sent. In particular for AXFR, that means that if the message is to be signed with, e.g., TSIG this must be done before the padding is applied.


# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.



--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
