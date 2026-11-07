# Email identity investigation playbook

## When an address fails technical checks
1. Re-check the address to rule out transient DNS errors.
2. Confirm the address with the person through an existing trusted channel; typos are the most common cause.
3. If the domain lacks mail infrastructure, the address cannot receive mail; request an alternative address.

## When authentication records are missing (your own domains)
1. Publish SPF covering all senders, keep it under 10 lookups.
2. Enable DKIM signing for each sending platform with 2048-bit keys.
3. Publish DMARC with reporting, then move to quarantine/reject.

## When suspicious indicators are present
1. Review the evidence for each finding and its confidence.
2. Check tenant threat intelligence and abuse reports.
3. If indicators are corroborated, open an investigation case in Incident Management from the email record; attach the Sentrix report.
4. Do not take adverse action against a person based solely on an email check; use proportionate, human-reviewed processes.

## Privacy
Collect only the addresses needed for a stated purpose, record that purpose with every check, and do not probe mailboxes.
