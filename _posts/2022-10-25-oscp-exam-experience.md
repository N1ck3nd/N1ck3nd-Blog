---
title: 'OSCP Exam Experience'
date: 2022-10-25 20:55:00 +0800
categories: [Certifications]
tags: [oscp]
image:
  path: /assets/posts/2022-10-25-OSCP-Exam-Experience/thumbnail.png
---

I passed the OSCP exam with 90 points (80 + 10 bonus points)!

# Background

I am a 21-year-old IT professional from the Netherlands who has worked in IT for nearly 4 years. After doing my internship at a cybersecurity company, I was offered a job while I was still in college. At the end of 2020, I graduated from college, after which I started working full-time. By the time I graduated, I was fairly familiar with the basics of IT (Windows Administration, Active Directory, Linux, Networking, etc.).

In April, 2021, I signed up for a TryHackMe subscription and started studying. I ended up completing the Complete Beginner, Web Fundamentals, and Offensive Pentesting paths. My goal was to sign up for the PWK course, get my OSCP, and land a job as a Penetration Tester. After learning the fundamentals of hacking, I got started doing more boxes on TryHackMe which I did for a couple of months. I completed about 155 boxes prior to signing up for the PWK course.

# Preparation

After talking to a colleague who had recently earned his OSCP, I decided to sign up for the Learn One subscription (paid for by my employer) and pursue the OSCP certification. On the 25th of November, 2021, I received access to the PWK course.

I jumped straight into the labs, but after finding myself a bit daunted, I figured it would not be a bad idea to go through the first few chapters of the course materials first. A few days later, I got started in the labs and popped my first shell. Over the course of the next few weeks I would continue to root boxes in the labs.

Around the end of February, I took a break which meant I did not practise for several weeks.

Returning back to where I had left, I kept hitting boxes that had dependencies in the PWK lab network. I ended up doing nearly 40 machines in the PWK lab environment. After reading up on some blog posts online, I resorted to doing Proving Grounds instead.

I enjoyed doing the Proving Grounds boxes and, like many others, I used TJnull’s list. Until the week of my exam, I had completed 25 Play boxes and 26 Practice boxes. While doing PG boxes, I signed up for CyberSecLabs and completed all Active Directory boxes.

After another break and not being able to study for nearly a month, I finally decided to schedule the OSCP exam for the 21st of October, 2022.

About 4 weeks before my exam I signed up for Hack The Box and completed 26 boxes (mostly easy / medium Windows boxes from TJnull’s list). In the week of my exam, I spent some extra time on Buffer Overflows (TryHackMe — BOF practice) and practised pivoting using my dedicated Windows VMs in the PWK labs.

On the day before my exam, I reviewed my rather extensive notes which I had been keeping ever since I started my journey doing TryHackMe. When I was just starting out, I would take notes in Hugo, but after a while I decided to switch to Obsidian. The night before my exam I enjoyed dinner with family and friends. Eventually, I took a short walk, meditated and went to sleep at 10:30 PM.

# Exam

As my exam was scheduled to start at 9 AM, I got out of bed at 7 AM. I took a cold shower and went for a 30-minute walk. At 8:15 AM I turned on my PC while praying that everything would work. 30 minutes later, I checked in with the proctor and after that I was told to wait for my exam package which arrived at 9 AM. I connected to the VPN and started my exam.

After reverting all of the boxes to play it safe, I started enumerating the machines.

At 10 AM I was able to submit my first flag as I got a foothold on one of the machines. 1 hour later I had managed to escalate my privileges on the box. Around 12:30 PM, I took a break and ate a nutritious lunch (loads of protein and fats with some fruit and veggies) followed by another walk.

Eventually, by 3:30 PM, I had completed three machines and was ready to move on. At 3:40 PM I was sitting at 50 points as I had obtained a low-privileged shell on one of the other machines. Half an hour later I would obtain a root shell, which meant I had obtained enough points to pass the exam since I had done the new course exercises and completed enough machines in the PWK lab environment.

Feeling confident, I started working on the second standalone box. While I was working on the box, I took a break to eat dinner. Just before 7 PM I rooted the second standalone box. The third standalone box turned out to be much harder and eventually I did not end up getting a foothold on that box.

I went to sleep at 12:30 AM and woke up at 5:45 AM. Once reconnected to the exam environment, I started checking my notes and screenshots for a few hours. Eventually, around 8:30 AM, I ended my exam and started working on my exam report which I submitted by 4 PM on Saturday.

Sunday at 5:30 PM, I got confirmation that I had successfully completed the OSCP exam.

Some advice; listen to your body and take frequent breaks, stretch / get some exercise in, and eat nutritious and healthy foods. Not at one point did I feel exhausted or did I experience brain fog during the exam.

# Landing a Job

Put yourself out there and talk to people about where you want to take your career, because you might actually end up coming across individuals who can help you along the way. Also, do not trick yourself into believing that you need a certain certification before you can land a job as a Security Professional. I actually landed my first pentesting job the day before I took the OSCP exam. Networking can take you places and if you work hard, it shall most definitely pay off. Most importantly, don’t let anyone ever tell you that you can’t do something.

I tried harder, and so can you.
