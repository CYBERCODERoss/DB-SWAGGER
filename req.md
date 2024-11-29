> Machine Learning for Database Intrusion Detection
>
> Syed Saad Mohsin Talat Faheem Muhammad Usman
>
> Department of Cyber Security
>
> National University of Computing and Emerging Sciences Islamabad,
> Pakistan
>
> Email: 22i-1601@nu.edu.pk, 22i-1735@nu.edu.pk, 22i-1689@nu.edu.pk

Abstract—In modern organizational frameworks, safeguarding database
integrity and confidentiality is paramount. This paper presents an
advanced intrusion detection system tailored for database environments,
emphasizing identity-based access con-trol. The system is structured
around departmental identities, each associated with distinct
permissions that govern employee interactions with departmental
databases. An administrative layer oversees the creation and management
of these identities and their respective permissions. The core
functionality involves processing input queries from employees, wherein
the system verifies the employee’s identity against predefined
parameters set by the administrator. Subsequently, the system evaluates
the SQL query against the permissions linked to the identified role.
Approval is granted only if the query aligns with authorized
permissions.

To enhance security, we employ an unsupervised machine learning model,
trained on historical log data representing typical SQL query patterns
within each department. This model is adept at identifying anomalous
queries that deviate from the norm, effectively flagging potential
intrusions. The proposed system not only fortifies database security by
preventing unauthorized access but also leverages machine learning to
adaptively refine its de-tection capabilities. The integration of
identity-based permissions with machine learning-driven intrusion
detection constitutes a robust framework for maintaining database
security in dynamic and multi-user environments.

Keywords-Intrusion Detection System, Database Security, Identity-Based
Access Control, Unsupervised Machine Learn-ing, SQL Query Analysis,
Anomaly Detection, Permissions Management, Organizational Frameworks,
Access Control Policies, Data Integrity and Confidentiality

> I. INTRODUCTION

In today’s digital era, the exponential growth of online services has
led to organizations managing vast amounts of sensitive data.
Organizations’ databases contain critical infor-mation ranging from
financial transactions and customer de-tails to confidential business
contracts. This necessitates robust security measures to maintain data
integrity, confidentiality, and accessibility. Security breaches not
only result in substan-tial financial losses but also severely damage
organizational reputation and trust.

Our research introduces an advanced Identity-Based Database Protection
System (IDBPS) that integrates traditional access control mechanisms
with machine learning capabilities to detect and prevent unauthorized
database access. Unlike conventional systems that rely solely on
predefined rules, our approach combines identity-based permission
management with unsupervised learning algorithms trained on historical
query patterns.

The system addresses two primary security challenges: internal privilege
abuse and external unauthorized access at-tempts. Internal threats often
arise when employees misuse their assigned privileges, while external
threats typically in-volve attackers attempting to exploit system
vulnerabilities to gain unauthorized access. Traditional signature-based
de-tection systems fall short as they can only identify known attack
patterns. Our system’s unsupervised learning approach, however,
establishes normal query patterns for each identity-permission
relationship, enabling it to detect anomalous be-havior even in dynamic
database environments.

The framework implements a hierarchical structure where departmental
databases are accessed through specific identity roles, which can be
assigned to multiple employees. Each query is evaluated through a
dual-validation process: first checking against administrator-defined
identity permissions, and then analyzing query patterns through our
trained model. This approach effectively prevents unauthorized privilege
es-calation, identity misuse, and sophisticated SQL injection attacks.

Our system maintains detailed logs of database interactions, creating a
comprehensive profile of normal query patterns for each permission
level. The unsupervised learning model continuously adapts to evolving
query patterns, making it particularly effective in dynamic
organizational environments where database access patterns may change
over time. This approach significantly improves upon traditional
rule-based systems by providing adaptive security measures while
main-taining strict access control standards.

This research fills a critical gap in database security by introducing
an intelligent, learning-based approach to access

control that can automatically adapt to organizational changes while
maintaining robust security standards. The system’s effectiveness in
preventing both internal and external threats, combined with its ability
to adapt to evolving attack patterns, makes it a valuable contribution
to modern database security
infrastructure.<img src="./knobhh0o.png"
style="width:3.48699in;height:2.28514in" />

> II\. RELATED WORK

Numerous intrusion detection systems have been devel-oped for host
systems and networks, yet there remains a relative scarcity of
significant efforts specifically targeting database intrusion detection.
One of the earlier approaches was introduced by Chung and colleagues,
who proposed a misuse detection strategy that involved mining frequent
data patterns to establish normal profiles. However, this method’s main
limitation is its failure to account for role-specific profiles, as
users often perform actions based on their roles, rendering user
profiles alone insufficient. Lee and associates put forward a real-time
intrusion detection system that relies on time signatures. This approach
is particularly suited for real-time database systems that utilize
temporal data objects, which change over time. When temporal data is
updated, a sensor transaction is triggered, and any attempt to alter the
already updated temporal data raises an alert. Nonetheless, this method
primarily focuses on updates and neglects role-specific profiles. Hu
Panda’s method employs log files to create user profiles by storing
frequently accessed data and tables for comparison. The challenge with
this approach lies in the difficulty of maintaining data as database
size and user numbers grow dynamically. Bertino and colleagues developed
a methodology that creates normal profiles for roles to detect anomalous
patterns, employing a naive Bayes classifier to identify suspicious SQL
queries. Unfortunately, this approach suffers from a high false
detection rate, where legitimate queries are mistakenly flagged as
malicious, thus hindering access for authorized users. Kamra et al.
introduced a data structure called Triplet, which records three aspects
of the SQL query, also utilizing a naive Bayes classifier to build
normal role profiles. However, this system does not consider
correlations between queries or information contained in the WHERE
clause. Hashemi’s approach involves mining correla-tions among data
items, with each item treated as time series data. CA. Ronao and
collaborators applied principal compo-nent analysis and random forests
to classify malicious queries, but this method did not significantly
improve detection rates compared to the naive Bayes classifier and was
ineffective against SQL injection and insider threats. Indu Singh’s
pro-posal relies on a Counting Bloom Filter and token management but
fails to detect inference from complex dynamic queries and does not
address privilege escalation. Niklas Rappel’s approach, which uses a
weighted naive Bayes classifier and the MLMS approach, struggles with
performance during frequent weight updates and is ineffective in
detecting insider attacks. Saad M. Darwish’s method employs a naive
Bayes classifier with a hexplet data structure for transaction-based
analysis rather than query-based, but it requires role-related
information

in log files and incurs substantial overhead due to the dynamic nature
of database structures and sizes. This research paper seeks to address
these limitations by developing a system that integrates identity-based
access control with unsupervised machine learning for anomaly detection,
offering a more adaptive and comprehensive solution to database
intrusion detection.

> III\. PROPOSED SYSTEM

The proposed solution is an intrusion detection system specifically
designed for safeguarding database environments within organizations.
The system uses an identity-based access control mechanism to ensure
that employees interact with departmental databases in a secure and
authorized manner. Each department is associated with unique identities,
and these identities have specific permissions that dictate the types of
SQL queries employees can execute. An administrative layer manages these
identities and permissions. The core of the system involves verifying
the identity of an employee against predefined parameters and
subsequently validating the SQL query against the permissions associated
with the identity. To enhance security further, the system employs
unsupervised machine learning to detect anomalies in query patterns,
thereby identifying potential intrusions. This dual approach of
identity-based access control combined with machine learning-driven
anomaly detection aims to provide a robust and adaptive solution for
maintaining database security.

> A. SYSTEM DESIGN

The system architecture is designed to seamlessly integrate with
existing database management systems while providing an additional layer
of security. The primary components of the system include the Identity
Manager, the Permissions Validator, the Machine Learning Anomaly
Detector, and the Query Validator.

Fig. 1. System Architecture for Database Access Control and Intrusion
Detection

A. Identity Manager

This component is responsible for managing the identities associated
with each department. It interfaces with the ad-ministrative layer to
create, update, and delete identities and their associated permissions.
Each identity is linked to multiple employees, and the Identity Manager
ensures that the correct identity is associated with each incoming
query.

B. Permission Validator

Once an identity is established for an incoming query, the Permissions
Validator checks the SQL query against the per-missions defined for that
identity. This component ensures that only authorized queries are
executed, preventing unauthorized access to sensitive data.

C. Machine Learning Anomaly Detector

This component is integrated to provide an additional secu-rity layer by
identifying anomalous patterns in SQL queries. It uses unsupervised
learning algorithms trained on historical query logs to establish a
baseline of normal activity for each department. Queries that deviate
significantly from this baseline are flagged for further inspection.

D. Query Validator

After passing through the Permissions Validator and Anomaly Detector,
the Query Validator performs a final check to ensure that all security
protocols have been adhered to before the query is executed on the
database.

> B. MACHINE LEARNING COMPONENT

The Machine Learning Anomaly Detector is a critical component that
leverages the power of machine learning to enhance the system’s ability
to detect intrusions. We em-ploy unsupervised learning algorithms such
as clustering and anomaly detection models, which are trained on
historical SQL query logs. The choice of unsupervised learning is driven
by the need to identify patterns and anomalies without requiring labeled
data.

A. Data Preprocessing

Historical query logs are first preprocessed to extract rele-vant
features, such as query type, frequency, and complexity. This
preprocessing step is crucial for transforming raw log data into a
format suitable for machine learning.

B. Model Training

The preprocessed data is used to train the anomaly detec-tion model.
Techniques such as clustering (e.g., K-Means) or density-based methods
(e.g., DBSCAN) are employed to identify clusters of normal behavior.
Queries that fall outside these clusters are considered anomalous.

C. Real-time Monitoring

Once the model is trained, it is deployed in the system to monitor
incoming queries in real-time. The model continu-ously updates its
understanding of normal behavior, allowing it to adapt to changes in
query patterns over time.

> C. VALIDATION OF QUERIES

The validation process is a multi-step approach designed to ensure that
only authorized and non-anomalous queries are executed. This process
involves several layers of checks:

A. Identity Verification

The first step in query validation is verifying the identity of the
employee submitting the query. This is achieved through the Identity
Manager, which ensures that the query is associ-ated with a recognized
and authorized identity.

B. Permissions Check

The Permissions Validator then examines the query to en-sure it aligns
with the permissions associated with the verified identity. This check
prevents unauthorized access to database resources.

C. Anomaly Detection

The Machine Learning Anomaly Detector analyzes the query for any unusual
patterns that may indicate malicious intent or accidental misuse.
Queries flagged as anomalous are subjected to further scrutiny.

D. Final Validation

The Query Validator performs a final check to ensure compliance with all
security protocols before execution. If a query passes all these checks,
it is considered valid and is executed on the database.

> IV\. CONCLUSION AND FURURE WORK

The proposed intrusion detection system offers a comprehensive solution
for securing database environments through a combination of
identity-based access control and machine learning-driven anomaly
detection. By integrating these two approaches, the system not only
prevents unauthorized access but also adapts to evolving threats through
continuous learning. The system’s design ensures compatibility with
existing database infrastructures, making it a viable option for
organizations seeking to enhance their data security measures.

Future work will focus on further refining the machine learning
component to improve detection accuracy and reduce false positives.
Additionally, exploring the integration of su-pervised learning
techniques could provide new insights into query patterns and enhance
the system’s overall performance. Expanding the system’s capabilities to
include real-time alerts and automated responses to detected intrusions
is also a prior-ity. These enhancements will ensure that the system
remains robust and effective in an ever-changing security landscape.

> REFERENCES

\[1\] R. J. Santos, J. Bernardino, and M. Vieira, "Approaches and
Challenges in Database Intrusion Detection," \*SIGMOD Record\*, vol. 43,
no. 3, pp. 36-47, Sep. 2014.

\[2\] S. J. Kamalanathan and K. Kandasamy, "Database In-trusion
Detection System Using Octraplet and Machine Learn-ing," in
\*Proceedings of the 2nd International Conference on Inventive
Communication and Computational Technologies (ICICCT 2018)\*, Kollam,
India, Sep. 2018, pp. 1413–1416.

\[3\] C. Y. Chung, M. Gertz, and K. Levitt, "DEMIDS: A mis-use detection
system for database systems," in \*Proceedings of the 3rd International
Working Conference on Integrity and Internal Control in Information
Systems\*, Netherlands, Nov. 2014.

\[4\] V. Lee, J. Stankovic, and S. Son, "Intrusion detection in
real-time database systems via time signatures," in \*Proceed-ings of
the 6th IEEE Real-Time Technology and Applications Symposium\*, USA, May
2000.

\[5\] Y. Hu and B. Panda. "Identification of malicious trans-actions in
database systems," in \*Proceedings of the 7th Inter-national Database
Engineering and Applications Symposium\*, Hong Kong, Jul. 2003.

\[6\] E. Bertino, A. Kamra, E. Terzi, and A. Vakali, "Intrusion
detection in RBAC-administered databases," in \*Proceedings of the 21st
Annual Computer Security Applications Confer-ence\*, USA, Dec. 2005.

\[7\] I. Singh, L. Kejriwal, and A. Agarwal, "Conditional
adherence-based classification of transactions for database in-trusion
detection and prevention," in \*International Conference on Advances in
Computing, Communications and Informatics (ICACCI)\*, 2016.

\[8\] A. Kamra, E. Bertino, and G. Lebanon, "Mechanisms for database
intrusion detection and response," in \*Proceedings of the 2nd SIGMOD
PhD Workshop on Innovative Database Research\*, Canada, Jun. 2008.

\[9\] S. Hashemi, Y. Yang, D. Zabihzadeh, and M. Kangavari, "Detecting
intrusion transactions in databases using data item dependencies and
anomaly analysis," in \*Expert Systems\*, 2008.

\[10\] C. A. Ronao, "Mining SQL queries to detect anomalous database
access using Random Forest and PCA," in \*In-ternational Conference on
Industrial, Engineering and Other Applications of Applied Intelligent
Systems\*, 2015.

\[11\] I. Singh, T. Singh, and T. V. Singh, "Detecting intrusive
malicious transactions in databases using session and token management,"
in \*International Conference on Computer Sys-tems, Data Communication
and Security\*, GRENZE Scientific Society, 2015.

\[12\] J. Bu and S.-B. Cho, "A hybrid system of deep learning and
learning classifier system for database intrusion detection," in
\*Proceedings of the 12th International Conference on Hy-brid Artificial
Intelligence Systems (HAIS 2017)\*, Springer, LNAI, vol. 10334, Jun.
2017, pp. 615–625.

\[13\] N. Rappel, "Dynamic intrusion detection in database systems: A
machine-learning approach," in \*ICIS Proceed-ings\*, Dublin, Ireland,
2016.

\[14\] S.-J. Bu and S.-B. Cho, "A convolutional neural-based learning
classifier system for detecting database intrusion via insider attack,"
\*Information Sciences\*, 2019.

\[15\] S. M. Darwish, "Journal of Electrical Systems and Information
Technology," vol. 3, issue 2, Sep. 2016.

\[16\] M. Doroudian and H. R. Shahriari, "Database intru-sion detection
system for detecting malicious behaviors in transaction and
inter-transaction levels," in \*7th International Symposium on
Telecommunications (IST)\*, 2014.

\[17\] G. Holmes, A. Donkin, and I. H. Witten, "WEKA: A machine-learning
workbench," in \*Proceedings of the ANZIIS ’94 - Australian New Zealand
Intelligent Information Systems Conference\*, 1994.

\[18\] S. M. Darwish, "Machine learning approach to detect intruders in
a database based on hexplet data structure," \*Journal of Electrical
Systems and Information Technology\*, vol. 3, no. 1, pp. 1–9, 2016.
