
<img width="1108" height="883" alt="image" src="https://github.com/user-attachments/assets/b9da46cb-5c0a-44ca-8712-bfe0dd60fa0e" />

<img width="759" height="64" alt="image" src="https://github.com/user-attachments/assets/d6bb648c-1a28-49b2-af76-f962837ed5e3" />

# Recon

```
How many emails have malicious PDFs? (Example: OmniCTF{67})
Arrange the emails the attacker used to send the PDFs alphabetically from a -> z? (Example: OmniCTF{abc@andydwdhhdd.net+test@omnictf.com})
What is the first malicious HTTP download URL in the PCAP? (Example: OmniCTF{url})
How many unique remote IP-and-port combinations use the Qakbot TLS client fingerprint? (Example: OmniCTF{67})
Identify all unique Qakbot TLS C2 endpoints, separated by +, in ascending order. (Example: OmniCTF{192.168.11.0:80+192.168.11.3:443})
At what timestamp is the malicious ZIP requested? (Example: OmniCTF{YYYY-MM-DD HH:MM:SS})
At what timestamp is the Qakbot DLL requested? (Example: OmniCTF{YYYY-MM-DD HH:MM:SS})
How many seconds pass between DLL GET and first C2 ClientHello? (Example: OmniCTF{6.767})
What malware family is represented? (Example: OmniCTF{Fam})
What is the malware campaign/variant identifier? (Example: OmniCTF{Mal})

```


Q1 -> How many emails have malicious PDFs? (Example: OmniCTF{67})

```
grep -l "Content-Type: application/pdf" *.eml | wc -l 
```

@2 -> Arrange the emails the attacker used to send the PDFs alphabetically from a -> z? (Example: OmniCTF{abc@andydwdhhdd.net+test@omnictf.com})

```
for f in Email*.eml; do
    if grep -q "Content-Type: application/pdf" "$f"; then
        grep "^From:" "$f"
    fi
done
```

```
cat Email3.eml                                                                                                                                                                         ✭
Delivered-To: [recipient's email address]
Return-Path: <bounce+84921-4f93@[campaign-mail.example]>
Received: from inbound-gateway.recipient.example (inbound-gateway.recipient.example. [192.0.2.12])
        by [recipient's mail server] with ESMTPS id 20020a05600c4f8c00b003f6021f1d8fsi1867219wmq.93.2023.05.24.09.05.56
        for <[recipient's email address]>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 May 2023 09:05:56 -0700 (PDT)
Received-SPF: pass ([recipient's mail server]: domain of bounce+84921-4f93@campaign-mail.example designates 198.51.100.204 as permitted sender) client-ip=198.51.100.204;
Authentication-Results: [recipient's mail server];
       dkim=pass header.i=@campaign-mail.example header.s=mail2023 header.b=CTF03B77;
       spf=pass ([recipient's mail server]: domain of bounce+84921-4f93@campaign-mail.example designates 198.51.100.204 as permitted sender) smtp.mailfrom=bounce+84921-4f93@campaign-mail.example;
       dmarc=fail (p=quarantine sp=quarantine dis=none) header.from=castillo-lane.example
Message-ID: <84921.4f93.1684944352@smtp4.campaign-mail.example>
Received: from smtp4.campaign-mail.example (smtp4.campaign-mail.example. [198.51.100.204])
        by inbound-gateway.recipient.example with ESMTPS id 42B89E7C
        for <[recipient's email address]>
        (version=TLS1_2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256/256);
        Wed, 24 May 2023 16:05:55 +0000
Received: from app-worker-17.internal.campaign-mail.example (app-worker-17.internal.campaign-mail.example. [10.31.6.17])
        by smtp4.campaign-mail.example with ESMTP id 84921-4f93
        for <[recipient's email address]>;
        Wed, 24 May 2023 16:05:53 +0000
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=campaign-mail.example; s=mail2023;
        h=from:to:reply-to:subject:date:message-id:mime-version:content-type:list-unsubscribe;
        bh=Q1RGX0lOVEVOVElPTkFMTFlfSU5WQUxJRF9IQVNI; b=CTF03B77hgovy69qi5kNFyA
        dLZJaxiwSxG16PZYVxDGlgEgI19HpEJnUlJZJkA10P0xRbXHiHUA10xurr5AiFMAMA
        5KLPUuaC9wA10pGLkceISAAAA8CjxXgO3LAAAA83oc9M9CAAAA87YfXLusrAAAA8
        QeOCbCzCf774FzkUdFQA9oLFJaKGuiEWpK2IO21WS7VecoQA10QEXdDO2ut3YA10
        h85rdfYkAAAA8SSmOFEACAAAA8RqOAJGx8AAAA8c9u8yU814wifJhuwHsA9CTF03;
From: Castillo Lane Sales Department <ventas@castillo-lane.example>
Sender: xaney@emplo.com
Reply-To: castillo-lane-documents@webmail-support.example
Date: Wed, 24 May 2023 19:05:52 +0300
Subject: =?UTF-8?Q?RE=3A_Requested_sales_documents?=
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="=_campaign_84921_1684944352"
List-Unsubscribe: <mailto:unsubscribe@campaign-mail.example?subject=84921-4f93>,
 <https://unsubscribe.campaign-mail.example/u/84921/4f93>
List-Unsubscribe-Post: List-Unsubscribe=One-Click
Precedence: bulk
X-Campaign-ID: 84921
X-Campaign-Source: imported-contact-list
X-Entity-ID: customer-document-notice
X-Report-Abuse: abuse@campaign-mail.example
X-Tracking-ID: 4f93-84921-1684944352
X-Mailer: CampaignEngine/6.4

--=_campaign_84921_1684944352
Content-Type: multipart/alternative; boundary="=_alternative_84921_4f93"

--=_alternative_84921_4f93
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: quoted-printable

Hello,

You can find the requested sales documents in the attached file. Please =
reply once they have been reviewed.

Best regards,
Castillo Lane Sales Department

--=_alternative_84921_4f93
Content-Type: text/html; charset=utf-8
Content-Transfer-Encoding: quoted-printable

<!doctype html>
<html>
<head>
<meta charset=3D"utf-8">
<title>Requested sales documents</title>
</head>
<body style=3D"font-family:Arial,Helvetica,sans-serif;color:#222">
<p>Hello,</p>
<p>You can find the requested sales documents in the attached file. Please =
reply once they have been reviewed.</p>
<p>Best regards,<br>Castillo Lane Sales Department</p>
<p style=3D"font-size:10px;color:#888">Sent through an automated document =
delivery service.</p>
</body>
</html>
[...]
```

Q3 -> What is the first malicious HTTP download URL in the PCAP? (Example: OmniCTF{url})

```
tshark -r 2023-05-24-obama264-Qakbot-infection.pcap -Y "http.request.method == GET" -T fields -e frame.time -e http.host -e http.request.uri | head -1
```

Q4 -> How many unique remote IP-and-port combinations use the Qakbot TLS client fingerprint? (Example: OmniCTF{67}) &
Q5 Identify all unique Qakbot TLS C2 endpoints, separated by +, in ascending order. (Example: OmniCTF{192.168.11.0:80+192.168.11.3:443})

```
tshark -r 2023-05-24-obama264-Qakbot-infection.pcap -Y "tls.handshake.type == 1 and ip.src == 10.5.24.101" -T fields -e ip.dst -e tcp.dstport -e tls.handshake.extensions_server_name -e tls.handshake.ciphersuite -e tls.handshake.extensions_supported_groups
```
Q6 -> At what timestamp is the malicious ZIP requested? (Example: OmniCTF{YYYY-MM-DD HH:MM:SS})

```
tshark -r 2023-05-24-obama264-Qakbot-infection.pcap -Y "http.request.uri contains \".zip\"" -T fields -e frame.time -e http.response.code -e http.content_length
```

Q7 -> At what timestamp is the Qakbot DLL requested? (Example: OmniCTF{YYYY-MM-DD HH:MM:SS})

```
tshark -r 2023-05-24-obama264-Qakbot-infection.pcap -Y "http.request.method == GET" -T fields -e frame.time -e http.host -e http.request.uri
```

Q8 -> How many seconds pass between DLL GET and first C2 ClientHello? (Example: OmniCTF{6.767})

```bash
dll_epoch=$(date -d "2023-05-24T16:35:27.396568+0000" +%s.%N)
c2_epoch=$(date -d "2023-05-24T16:41:06.722361+0000" +%s.%N)
echo "$c2_epoch - $dll_epoch" | bc
```

Rez -> 1684946466.722361000 - 1684946127.396568000 = 339.325793 = ~339.326

Q9 -> What malware family is represented? (Example: OmniCTF{Fam})

```
PCAP filename contains Qakbot
Qakbot's JA3 fingerprint confirms the malware family
```
Q10 -> What is the malware campaign/variant identifier? (Example: OmniCTF{Mal})

```
/ewukhyqpjz/ewukhyqpjz.zip
```









