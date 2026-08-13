---
id: risk_score_arithmetic
title: Unified Risk Score & Arithmetic
tags: [score, posture, drivers, math, arithmetic]
summary: How SentinelAI calculates your 0-100 overall security posture score.
---

Your overall score is a weighted arithmetic average of three components: Privacy (40%), Browsing (40%), and Identity (20%). The system uses time-decayed aggregation where recent incidents impact your score more heavily. An unmeasured component is rendered as null rather than safe, so missing checks do not inflate your score.
