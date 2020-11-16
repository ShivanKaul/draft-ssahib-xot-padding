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

{{I-D.draft-ietf-dprive-xfr-over-tls}} specifies use of TLS to prevent zone content collection via passive monitoring of zone transfers (Zone Transfer over TLS: XoT). RFC 7830 specifies the EDNS(0) 'Padding' option, but does not specify the actual padding length for specific applications. This memo lists the possible options ("Padding Policies") for using padding in combination with XoT and discusses the implications of each of these options.

--- middle

# Introduction

{{I-D.draft-ietf-dprive-xfr-over-tls}} outlines the threat model considered in the design of XoT which focusses on the protection of the zone contents tranfered in zone transfer responses. It briefly outlines the motivations for also padding those zone transfer responses but does not provide detailed guidance on what padding policy should be used. This document attempts to enumerate in more detail the meta data about the zone contents that might still be deduced or infered by inspecting encrypted zone transfers and proposes padding policies to mitigate the leakage of such information.

This draft provides separate discussions on padding of full zone transfers to obfuscate the actual size of the transferred zone, and on padding incremental zone transfers to obfuscate the incremental changes to the zone to minimize information leakage about zone update activity and growth.

# Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 {{RFC2119}} {{!RFC8174}}
when, and only when, they appear in all capitals, as shown here.

# Threat Model

Even when using XoT to protect transfered zone contents, there are other sources of information about zones that an attacker can leverage to gather information about the zone and its update activity. We assume the attacker in question is able to passively monitor the traffic on a link between two of the authoritative nameservers for the zone (hence the requirement for XoT).

NOTE: We explicitly exclude the case where an attacker can actively monitor 

* any of the query traffic to the authoritative in this analysis and/or
* any channel involved in unencrypted zone updates (e.g. DNS Dynamic updates) 

If this is the case it introduces a large number of variables with regard to the other data the attacker might have access to, but they do not fundamentally change the conclusions here.

On this basis we additionally assume that for a particular zone the attacker:

* knows that the zone exists and is hosted authoritatively on the nameserver since they can
    * can directly observe when NOTIFYs are sent by the primary
    * can directly observe when unencrypted SOA queries are made by the secondary
    * or obtain this information via other out of band methods
* knows all the published nameservers for the zone (NS records)
* can actively and periodically directly query for the SOA for the zone via DNS queries to the published nameservers (although there may be a propagation delay in this compared to updates at the monitored servers)
* knows if the zone is DNSSEC signed and the signature lifetimes

The extent to which an attacker can enumerate the zone depends on whether it is DNSSEC signed, and whether it uses NSEC or NSEC3. Since NSEC signed zones are trivially enumerated, we confine this analysis to the use of XoT for either unsigned or NSEC3 signed zones. 

On this basis, the knowledge that an attacker could still gather by monitoring encrypted zone transfers and correlating encrypted traffic with unencrypted events includes:

* (AXFR) Zone size at a given point in time
* (AXFR) Zone growth over time
* (IXFR) An estimated range of the number of records modified in a given update
* (IXFR) An esimate of the zone size for dynamic DNSSEC signed zones that are rarely updated (due to IXFRs triggered due to resigning)
* ??

Factors that will complicate or defeat the extraction of such data by traffic analysis include:

* Do the pair of servers involved in transfers both host more than one zone?
   * Do they re-use the same connections for all the zones?
   * Do they re-use the same connections for both AXFR and IXFR?
* If the zone is DNSSEC signed and how
* ??

## Why is such data leakage sensitive?

It's not uncommon that in some organisations, the name of the zone might indicate its purpose and therefore knowing the size of the zone or how active it is might reveal general information about that organisations practices or activities. Depending on the organisation this could extend to information about specific individual, companies or growth in specific business areas. It could also reveal specific maintanance activies or deployment of new features.


# Padding for AXoT

As mentioned in {{I-D.draft-ietf-dprive-xfr-over-tls}}, the goal of padding AXoT responses would be two fold:

- to obfuscate the actual size of the transferred zone to minimize information leakage about the entire contents of the zone.
- to obfuscate the incremental changes to the zone between SOA updates to minimize information leakage about zone update activity and growth.

As with any padding strategy the trade-off between increased bandwidth and processing due to the larger size and number of padded DNS messages and the corresponding gain in confidentiality must be carefully considered.

As noted in [RFC8467], the maximum message length, as dictated by the protocol, limits the space for EDNS(0) options. Since padding will reduce the message space available to other EDNS(0) options, the "Padding" option MUST be the last EDNS(0) option applied before a DNS message is sent. In particular for AXFR, that means that if the message is to be signed with, e.g., TSIG this must be done before the padding is applied.

## Zone block size
A simplistic option, following the premise of the Block-Length Padding strategy recommended in [RFC8467], would be to simply specify a 'zone block size' for a zone - the sum total of all the AXFR responses should be padded to a multiple of this size. The number of responses used to reach this size could additionally be specified, or this could be left to the implementation. In either case, the size to which each individual response is padded MUST be the same in order to obfuscate any pattern in the underlying data. The details of how this is acheived can be implementation specific but a simple option would be to 

* put a fixed number of RRs in each response while there is data to send
* pad the response to a fixed size (S), 
* adding 'empty' responses padded to the same size S prior to sending the final response
* send the final response (containing the last SOA record), padded to size S

The implementation would be required to perform some precalculation to estimate the size of the zone on the wire in order to know the number of responses that will be required. 

Observation of the zone transfers would then reveal only zone block size step changes in the total zone size (if the zone size changed sufficiently) obfuscating the smaller fluctuations.

Choosing a zone block size close to the current zone size would provide some protection with a minimal overhead. Choosing a zone block size much larger than the current zone size would provide increased protection but with increased overhead.

## Zone step size

An alternative approach that could be taken is to specify a minimum zone size and an block size for incremental overhead on that block size.....



## Recommendations

Primary implementations SHOULD provide a configurable zone block size based padding mechanism.

## Examples

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


# Configurable Parameters
When we decide the configurable parameters - zone block size, message block size, we should consider the following things:
* The number of zones can be transfered between the primary and a secondary
* The frequency that the zone is updated
* Persistent connection is used or not
* Size of the zone
* The zone is signed or not

## Zone Block Size
Zone block size should be at least two times of the original zone length. As we cannot hide whether the zone is signed, and NSEC or NSEC3 is used, the zone block size should also be at least two times of the length of the signed zone.

## Message Block Size
* AXoT: As the AXoT reponses are usually large, the signed zones and unsigned zones can use the same message block size.
* IXot: For the same change, a signed zone has more reponses to send than an unsigned zone, the message block size for a signed zone should be larger for an unsigned zone.
 

# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.



--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
