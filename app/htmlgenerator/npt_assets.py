# Vulnerability_Count_Table
VULTABLE='<h3 class="list-level-1"><b>IP/Hostname Wise Vulnerability Count:-</b></h3><table class="vulcount"><tbody><tr><th rowspan="2">Sl. No.</th><th rowspan="2">IP Address</th><th colspan="5">Vulnerability Type</th><th rowspan="2">Total</th></tr><tr><th class="Critical">Critical</th><th class="High">High</th><th class="Medium">Medium</th><th class="Low">Low</th><th class="Informational">Informational</th></tr>{hosts}<tr><td colspan="2"><b>Overall Findings</b></td>{totalCounts}</tr></tbody></table>'

VULTABLE_HOSTS='<tr><td>{sl}</td><td>{address}</td><td class="Critical">{critical}</td><td class="High">{high}</td><td class="Medium">{medium}</td><td class="Low">{low}</td><td class="Informational">{info}</td><td class="Purple">{total}</td></tr>'

VULTABLE_TOTAL_COUNTS='<td class="Critical">{critical}</td><td class="High">{high}</td><td class="Medium">{medium}</td><td class="Low">{low}</td><td class="Informational">{info}</td><td class="Purple">{total}</td>'


#host wise vulnerability table
HOST_VULTABLE='<table class="vulnTable"><tbody><tr><th width="10%"><b>Sl. No.</b></th><th>Vulnerability Name</th><th width="12%">Risk Level</th><th width="10%">CVSS Score</th></tr>{hosts}</tbody></table>'
HOST_VULTABLE_VULS='<tr><td>{sl}</td><td>{name}</td>{risk}<td>{cvss_score}</td></tr>'
HOST_VULTABLE_RISK_LEVEL='<td rowspan="{rowspan}" class="{risk_factor}">{risk_factor}</td>'
HOST_NO_VUL_FOUND='<h3 class="list-level-3">No Vulnerabilities Found</h3>'
HOST_IS_DOWN='<h3 class="list-level-3">Host is down</h3>'

# Host wise open ports table
HOST_OPEN_PORT_TABLE='<h3 class="heading-2">Open Port Detail:</h3><table class="vulnTable"><tbody><tr><th colspan="2"><b>Port</b></th><th>State</th><th>Service</th><th>Version</th></tr>{ports}</tbody></table>'
HOST_OPEN_PORT_TABLE_PORTS='<tr><td width="10%">{port}</td><td width="10%">{protocol}</td><td>{state}</td><td>{service}</td><td>{version}</td></tr></tr>'
HOST_NO_PORTS_FOUND='<h3 class="heading-2">No Open Ports Found</h3>'


# VUlnerability wise table
VULWISE_TABLE='''<br><br><table class="vulwise vul{risk_factor}">
  <tbody>
    <tr class="{risk_factor}">
      <th colspan="3">
        <b style="margin-left: 0.63cm; font-size: 16pt;">{sl}. Vulnerability Name: </b>{name}<br>
        <b style="margin-left: 1.27cm; font-size: 16pt;">Vulnerability Rating: </b>{risk_factor}
      </th>
    </tr>
    <tr>
      <td colspan="3">
        <b class="text{risk_factor}">CVSS: </b>{cvss_score}
        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
        {cvss_vector}&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;{cvss_classification}
      </td>
    </tr>
    <tr>
      <td colspan="3">
        <b class="text{risk_factor}">Affected Systems: </b>
        <p style="font-size: 10pt; text-align: justify; display:inline-block;">
          {hosts}
        </p>
      </td>
    </tr>
    <tr>
      <td width="217" valign="top">
        <b class="text{risk_factor}">Vulnerability Description: </b>
      </td>
      <td colspan="2" style="font-size: 10pt; text-align: justify">
        <p style="font-size: 10pt">
          {description}
        </p>
      </td>
    </tr>
    <tr>
      <td width="217" valign="top"><b class="text{risk_factor}">Impact: </b></td>
      <td colspan="2" style="font-size: 10pt; text-align: justify">
        <p style="font-size: 10pt">
          {impact}
        </p>
      </td>
    </tr>
    <tr>
      <td width="217" valign="top">
        <b class="text{risk_factor}">Remediation: </b>
      </td>
      <td colspan="2" style="font-size: 10pt; text-align: justify">
        <p style="font-size: 10pt">
          {remediation}
        </p>
        <p style="font-size: 10pt; text-align:left;">
          {reference_links}
        </p>
      </td>
    </tr>
    <tr>
      <td width="217" valign="top" colspan="3">
        <b class="text{risk_factor}">Proof of Concept: </b>
      </td>
    </tr>
    <tr>
      <td width="217" valign="top" colspan="3">
        
      </td>
    </tr>
    <tr><td><b class="text{risk_factor}">Closure Remarks: </b></td><td colspan="2"></td></tr>
    <tr>
      <td colspan="3" style="background-color: #d9d9d9" height="30px"></td>
    </tr>
  </tbody>
</table>
'''


