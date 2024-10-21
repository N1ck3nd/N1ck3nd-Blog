---
title: 'Hack The Box Pro Labs: P.O.O. Review'
date: 2024-10-21 12:40:00 +0800
categories: [CTF]
tags: [review]
image:
  path: /assets/posts/2024-10-21-HackTheBox-Pro-Labs-POO-Review/thumbnail.png
---

Recently, I decided to sign up for Hack The Box’s Pro labs subscription to challenge myself to explore scenarios I would otherwise not be able to explore with the standard Hack The Box Labs VIP subscription. Once my subscription was activated, I made it my goal to conquer the P.O.O. lab environment; it consists of two Windows machines and five flags.

The small Active Directory environment has been designed to challenge and enhance the player’s skill set in penetration testing and red teaming. Personally, I take a great interest in red teaming and Active Directory, so I thought that this lab would be a suitable place for me to start.

During my lab time, I faced several scenarios in which I was forced to dig deeper in order to uncover the next step to ultimately compromise the Active Directory environment. The lab allowed me to solidify my testing methodology in a few different areas and inspired me to come up with creative ways to bypass certain restrictions. Also, it turns out that the lab environment is shared with other players, and '[PowerView.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)' was not just put on one of the machines to help me get around file upload limitations.

I enjoyed the fact that the environment, along with its vulnerabilities and misconfigurations, closely resembles a part of a network that you would encounter in the real world. One of my personal goals was to be quiet, and to 'live off the land' as much as I could by using built-in Windows tools. Putting to use my previously-gained sysadmin and PowerShell skills is always good fun.

It took about two days to compromise the two machines and gather all five flags. While this was only a small network, the lab taught me a lot of valuable lessons. I also noticed that I was able to apply numerous concepts from [Zero-Point Security’s Red Team Ops course](https://training.zeropointsecurity.co.uk/courses/red-team-ops). Upon the completion of the P.O.O. Pro Lab, I got to download my certificate of completion.

<img src="/assets/posts/2024-10-21-HackTheBox-Pro-Labs-POO-Review/certificate-of-completion.png" alt="mitmweb Interface" width="1000"/>

All in all, I would highly recommend Hack The Box Pro Labs to anyone who is interested in offensive cybersecurity and enhancing their existing skill set. I really enjoyed attacking the P.O.O. lab environment and I am excited to move on to the next one.
