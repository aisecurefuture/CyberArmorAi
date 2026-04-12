import hudson.model.ParametersDefinitionProperty
import hudson.model.BooleanParameterDefinition
import hudson.model.ChoiceParameterDefinition
import hudson.model.StringParameterDefinition
import jenkins.model.Jenkins
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition
import org.jenkinsci.plugins.workflow.job.WorkflowJob

def jenkins = Jenkins.get()
def jobName = System.getenv('CYBERARMOR_SECURITY_JOB_NAME') ?: 'CyberArmorAI'
def pipelinePath = System.getenv('CYBERARMOR_SECURITY_JENKINSFILE') ?: '/repo/CyberArmorAi/Jenkinsfile.security'
def pipelineFile = new File(pipelinePath)

if (!pipelineFile.exists()) {
  println("[cyberarmor-jenkins] skipping security job seed; ${pipelinePath} is not mounted")
  return
}

def job = jenkins.getItem(jobName)
if (job == null) {
  job = jenkins.createProject(WorkflowJob, jobName)
  println("[cyberarmor-jenkins] created ${jobName} pipeline job")
} else if (!(job instanceof WorkflowJob)) {
  println("[cyberarmor-jenkins] ${jobName} exists but is not a Pipeline job; leaving it unchanged")
  return
}

job.setDefinition(new CpsFlowDefinition(pipelineFile.text, true))
job.removeProperty(ParametersDefinitionProperty)
job.addProperty(new ParametersDefinitionProperty([
  new ChoiceParameterDefinition('SCAN_PROFILE', ['pr', 'integration', 'scheduled'] as String[], 'Run the PR/CI gate, the local OpenBao integration verifier, or the scheduled security sweep.'),
  new BooleanParameterDefinition('RUN_DOCKER_SCOUT_PR', false, 'Build and scan local images during PR/CI runs.'),
  new StringParameterDefinition('DEFAULT_BRANCH', 'main', 'Default branch used for diff-based scans.'),
  new StringParameterDefinition('SCOUT_BUILD_SERVICES', 'control-plane,policy,detection,response,identity,siem-connector,compliance,runtime,proxy-agent,transparent-proxy,agent-identity,ai-router,audit,integration-control', 'Comma-separated docker compose services to build and scan.'),
  new StringParameterDefinition('ZAP_TARGET_URL', '', 'Optional baseline scan target for scheduled ZAP runs.'),
  new StringParameterDefinition('PROWLER_PROVIDER', 'aws', 'Prowler provider/module to run on scheduled scans.'),
  new StringParameterDefinition('PROWLER_ARGS', '', 'Additional arguments passed to Prowler on scheduled runs.'),
  new StringParameterDefinition('OPENBAO_COMPOSE_PROJECT', 'cyberarmor-openbao-ci', 'Compose project name used for the local OpenBao integration verifier.')
]))
job.save()

println("[cyberarmor-jenkins] seeded ${jobName} from ${pipelinePath}")
