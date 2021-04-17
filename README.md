# Graylog SSH fields extractor

Contains GROK patterns, pipeline rule and pipeline for extracting ssh fields.

## Supported log line formats/types
```
webbox sshd[5]: Accepted password 		for								trogper 		from 	75.78.56.189 	port 62538
webbox sshd[5]: Accepted publickey 		for 							pipeline-user 	from 	78.15.28.13 	port 40146
webbox sshd[5]: Failed password 		for 							gnats 			from 	203.159.80.41 	port 52028

webbox sshd[5]: Failed password 		for 	invalid user 			git 			from 	203.159.80.41 	port 44636
webbox sshd[5]: Invalid user 											dspace 			from 	203.159.80.41 	port 59062

webbox sshd[5]: Disconnected 			from 	authenticating user 	daemon 					203.159.80.41 	port 54878
webbox sshd[5]: Disconnected 			from 	invalid user 			contador 				203.159.80.41 	port 33642
webbox sshd[5]: Connection closed 		by 		authenticating user 	trogper 				75.78.56.189 	port 62337

webbox sshd[5]: Received disconnect 	from												 	203.159.80.41 	port 32772
```

## GROK patterns
```
SSH
(%{HOSTNAME} sshd\[%{POSINT}\]: %{SSH_MESSAGE:ssh_message} (for|by|from)( %{SSH_USER_ADJECTIVE:ssh_user_adjective} user)?( %{USERNAME:ssh_username}( from)?)? %{SSH_REMOTE_SOCKET})

SSH_REMOTE_SOCKET
(%{IP:ssh_rip} port %{POSINT:ssh_rport})

SSH_MESSAGE
(%{SSH_AUTH_RESULT:ssh_auth_result} %{SSH_AUTH_METHOD:ssh_auth_method}|%{SSH_CONNECTION:ssh_connection}|Invalid user)

SSH_AUTH_RESULT
(Accepted|Failed)

SSH_AUTH_METHOD
(password|publickey)

SSH_USER_ADJECTIVE
(authenticating|invalid)

SSH_CONNECTION
(Received disconnect|Connection closed|Disconnected)
```

## Resulting fields
```
ssh_message: Accepted password | Accepted publickey | Failed password | Failed password | Invalid user | Disconnected | Disconnected | Connection closed | Received disconnect

ssh_auth_method: password | publickey
ssh_auth_result: Accepted | Failed

ssh_username: USERNAME
ssh_user_adjective: authenticating | invalid

ssh_rip: IP
ssh_port: PORT
```