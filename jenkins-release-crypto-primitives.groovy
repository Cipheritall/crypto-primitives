/***************************************************************/
/****************** JENKINS-CRYPTO-PRIMITIVES-RELEASE LIB ****************/
/***************************************************************/

sh "wget -O ./jenkins-build-pipeline.groovy https://artifactory.tools.pnet.ch/artifactory/libs-release-local/ch/post/it/common/jenkins/pipeline/00.02.03.05/pipeline-00.02.03.05.jar!jenkins-build-pipeline.groovy"
commonBuildPipeline = load 'jenkins-build-pipeline.groovy'

public performRelease(projectName, gitUrl, branchName, autoMerge, mavenGoals, mavenParameters, workspace, releaseVersion, newSnapshotVersion, releaseEmail, useArtifactoryArtifactUploader, buildInfoArtifactName, releaseMessage) {
	// cancel release build if no release version is given
	if (releaseVersion.length() < 1) {
		error "no release version was given - please set this parameter!"
	}

	// calculate snapshot version if not given
	if (!newSnapshotVersion) {
		newSnapshotVersion = getNewSnapshotVersion(releaseVersion)
	}

	// log given parameters
	commonBuildPipeline.LOGGER('automerge', autoMerge)
	commonBuildPipeline.LOGGER('branch name', branchName)
	commonBuildPipeline.LOGGER('release version', releaseVersion)
	commonBuildPipeline.LOGGER('snapshot version', newSnapshotVersion)

	// checkout and merge branches
	stage('checkout') {
		step([$class: 'WsCleanup'])
		if (autoMerge == 'true') {
			commonBuildPipeline.LOGGER('automerge', "automerge was enabled, we merge ${branchName} into master")
			checkoutSource(gitUrl, branchName)
			mergeBranch(branchName)
		} else {
			commonBuildPipeline.LOGGER('automerge', "automerge was not enabled, we don't merge")
			checkoutSource(gitUrl, branchName)
		}
	}

	// run validity checks
	stage('update version') {
		checkAppVersionValidity(workspace, newSnapshotVersion)
		commonBuildPipeline.LOGGER('checkAppVersionValidity', "checkAppVersionValidity")

		//Find oldversion
		def pomFile = 'pom.xml'
		if (commonBuildPipeline.MAVEN_POM_NAME.size() > 0) {
			pomFile = commonBuildPipeline.MAVEN_POM_NAME.replace('-f ', '')
		}
		def project = readMavenPom file: "${workspace}/${pomFile}"
		def oldversion = project.version

		//Update pom.xml version
		commonBuildPipeline.LOGGER('service version', "set new service version ${releaseVersion} in pom.xml!")
		sh "mvn -s ${EVOTING_HOME}/.mvn/settings.xml ${commonBuildPipeline.MAVEN_POM_NAME} versions:set -DnewVersion=${releaseVersion}"
		sh "mvn -s ${EVOTING_HOME}/.mvn/settings.xml ${commonBuildPipeline.MAVEN_POM_NAME} versions:commit"
	}

	// run release build
	stage('release') {
		withEnv(["EVOTING_HOME=${env.WORKSPACE}"]) {
			RTMAVEN.deployer.deployArtifacts = useArtifactoryArtifactUploader
			// build maven command
			def mavenCommand = (mavenGoals != null ? mavenGoals + ' ' : '') + ' -DsnapshotDependencyAllowed=false -DupdateReleaseInfo=true -U -DaltDeploymentRepository=central::https://artifactory.tools.post.ch/artifactory/libs-release-evoting-local -DaltSnapshotDeploymentRepository=snapshots::https://artifactory.tools.post.ch/artifactory/libs-snapshot-evoting-local' + (mavenParameters != null ? ' ' + mavenParameters : '')
			if (commonBuildPipeline.MAVEN_POM_NAME.size() > 0) {
				commonBuildPipeline.LOGGER('RTMAVEN.run', "${mavenCommand}")

				//Deploy
				withCredentials([[$class: 'UsernamePasswordMultiBinding', credentialsId: 's-cicd-evoting', usernameVariable: 'GIT_USER', passwordVariable: 'GIT_PASS']]) {
					sh "mvn clean deploy -s ${EVOTING_HOME}/.mvn/settings.xml -DsnapshotDependencyAllowed=false -DupdateReleaseInfo=true -U -DaltDeploymentRepository=central::https://${GIT_USER}:${GIT_PASS}@artifactory.tools.post.ch/artifactory/libs-release-evoting-local -DaltSnapshotDeploymentRepository=snapshots::https://${GIT_USER}:${GIT_PASS}@artifactory.tools.post.ch/artifactory/libs-snapshot-evoting-local"
				}
			} else {
				commonBuildPipeline.LOGGER('RTMAVEN.run', "${mavenCommand}")
				//Deploy
				withCredentials([[$class: 'UsernamePasswordMultiBinding', credentialsId: 's-cicd-evoting', usernameVariable: 'GIT_USER', passwordVariable: 'GIT_PASS']]) {
					sh "mvn clean deploy -s ${EVOTING_HOME}/.mvn/settings.xml -DsnapshotDependencyAllowed=false -DupdateReleaseInfo=true -U -DaltDeploymentRepository=central::https://${GIT_USER}:${GIT_PASS}@artifactory.tools.post.ch/artifactory/libs-release-evoting-local -DaltSnapshotDeploymentRepository=snapshots::https://${GIT_USER}:${GIT_PASS}@artifactory.tools.post.ch/artifactory/libs-snapshot-evoting-local"
				}
			}

			tagAndCommit(projectName, gitUrl, releaseVersion, releaseMessage)
			// save artifacts with build info
			saveArtifacts(projectName, branchName, buildInfoArtifactName)
		}
	}

	// add sonar stuff

	// set new snapshot version and run snapshot build
	stage('set/build snapshot') {
		commonBuildPipeline.LOGGER('build snapshot', "automerge was enabled, we reset pom to Snapshot and rebuild on ${branchName}")
		resetPomVersion(projectName, workspace, gitUrl, branchName, releaseVersion, newSnapshotVersion)
		commonBuildPipeline.LOGGER("build", "current build status - ${currentBuild.result}")

		try {
			build job: "${projectName}/${branchName}", propagate: false, wait: false
			build job: "${projectName}", propagate: false, wait: false
		} catch (e) {
			commonBuildPipeline.LOGGER("build", "we don't started a SNAPSHOT build, because no job found for - project-name: '${projectName}' and/or branch-name: '${branchName}'")
		}

		commonBuildPipeline.LOGGER("build", "current build status - ${currentBuild.result}")
		if (releaseEmail) {
			sendReleaseEmail(projectName, releaseVersion, releaseEmail)
		} else {
			commonBuildPipeline.LOGGER('release email', 'no email was given per parameter')
		}
	}
}

/***************************************************************/
/*************** HELPER METHODS FOR JENKINS-RELEASE ****************/
/***************************************************************/

// merge given branch into master
def mergeBranch(branchName) {
	mergeBranch(branchName, "master")
}

// merge given branch into other branch
def mergeBranch(fromBranch, toBranch) {
	commonBuildPipeline.LOGGER('checkout', "branch - ${fromBranch} to ${toBranch}, autoMerge - true")

	//Checkout and Merge
	sh "git checkout ${toBranch} || git checkout master || exit"
	sh "git merge --squash -X theirs ${fromBranch} || exit"
}

// tag and commit into scm
def tagAndCommit(projectName, gitUrl, releaseVersion, releaseMessage) {
	def pomName = "pom.xml"
	if (commonBuildPipeline.MAVEN_POM_NAME != '') {
		pomName = commonBuildPipeline.MAVEN_POM_NAME.replace('-f ', '')
	}
	// commit all changes and tag newest commit
	//Add
	sh "git pull && git add --all"

	//Commit
	sh "git commit -m '${releaseMessage}'"

	//Tag
	sh "git tag -af ${projectName}-${releaseVersion} -m 'tag by jenkins ci'"

	//Push
	withCredentials([[$class: 'UsernamePasswordMultiBinding', credentialsId: 's-cicd-evoting', usernameVariable: 'GIT_USER', passwordVariable: 'GIT_PASS']]) {
		def url = gitUrl.replace('https://', '')
		sh "git push https://${GIT_USER}:${GIT_PASS}@${url} --all"
		sh "git push https://${GIT_USER}:${GIT_PASS}@${url} --tags"
	}
}

// reset pom to snapshotVersion
def resetPomVersion(projectName, workspace, gitUrl, branchName, releaseVersion, newSnapshotVersion) {
	def pomName = "pom.xml"
	if (commonBuildPipeline.MAVEN_POM_NAME != '') {
		pomName = commonBuildPipeline.MAVEN_POM_NAME.replace('-f ', '')
	}

	//Checkout
	sh "git checkout ${branchName} || git checkout master || exit"

	//Find oldversion
	def pomFile = 'pom.xml'
	if (commonBuildPipeline.MAVEN_POM_NAME.size() > 0) {
		pomFile = commonBuildPipeline.MAVEN_POM_NAME.replace('-f ', '')
	}
	def project = readMavenPom file: "${workspace}/${pomFile}"
	def oldversion = project.version

	//Update pom.xml version
	commonBuildPipeline.LOGGER('service version', "set snapshot service version ${newSnapshotVersion} in pom.xml!")
	sh "mvn -s ${EVOTING_HOME}/.mvn/settings.xml ${commonBuildPipeline.MAVEN_POM_NAME} versions:set -DnewVersion=${newSnapshotVersion}"
	sh "mvn -s ${EVOTING_HOME}/.mvn/settings.xml ${commonBuildPipeline.MAVEN_POM_NAME} versions:commit"

	//Add
	sh "git pull && git add --all"

	//Commit
	sh "git commit -m 'merge snapshot poms - ${projectName}-${releaseVersion}'"

	//Push
	withCredentials([[$class: 'UsernamePasswordMultiBinding', credentialsId: 's-cicd-evoting', usernameVariable: 'GIT_USER', passwordVariable: 'GIT_PASS']]) {
		def url = gitUrl.replace('https://', '')
		sh "git push https://${GIT_USER}:${GIT_PASS}@${url} --all"
		sh "git push https://${GIT_USER}:${GIT_PASS}@${url} --tags"
	}

	//Merge and push Release branche into develop (snapshot)
	sh "git checkout develop || exit"
	sh "git merge --squash -X theirs ${branchName} || git merge --squash -X theirs develop || exit"
	sh "git add ."

	//Commit
	sh "git commit -m 'merge snapshot poms - ${projectName}-${releaseVersion}'"
	withCredentials([[$class: 'UsernamePasswordMultiBinding', credentialsId: 's-cicd-evoting', usernameVariable: 'GIT_USER', passwordVariable: 'GIT_PASS']]) {
		def url = gitUrl.replace('https://', '')
		sh "git push https://${GIT_USER}:${GIT_PASS}@${url} --all"
		sh "git push https://${GIT_USER}:${GIT_PASS}@${url} --tags"
	}

}

// calculate new snapshot versions
def getNewSnapshotVersion(newversion) {
	def lastSegmentIndex = newversion.lastIndexOf(".") + 1
	def lastSegmentNumber = newversion.substring(lastSegmentIndex).toInteger()
	lastSegmentNumber++
	def snapshotversion = newversion.substring(0, lastSegmentIndex) + String.format('%02d', lastSegmentNumber) + "-SNAPSHOT"
	commonBuildPipeline.LOGGER('snapshot', "new snapshot number ${snapshotversion}")
	return snapshotversion
}

// get next tag from Git based on the latest one
def getNextTagFromGit(projectName, gitUrl, buildType) {
	def url = gitUrl.replace('https://', '')
	def latestTag = sh(script: "git ls-remote --tags https://${GIT_USER}:${GIT_PASS}@${url} | awk '!/\\{\\}/ {print substr(\$2,11,50)}' | sort -r | head -n 1", returnStdout: true).toString().trim()
	commonBuildPipeline.LOGGER('tag', "latest tag ${latestTag}")
	return getNextVersion(projectName, latestTag, buildType)
}

// calculate new tag from existing
// required input for existing: prefix-aa.bb.cc.dd
// the prefix is overwritten using the projectName
def getNextVersion(projectName, existingTag, buildType) {

	def versionPattern = ~'^[a-zA-Z0-9-_]+[0-9]{2}(\\.[0-9]{2}){3}'
	if (!existingTag || !versionPattern.matcher(existingTag).matches()) {
		error "existing tag is not valid - please check this parameter."
	}

	if (!projectName) {
		error "no projectName was given - please set this parameter."
	}

	def indexLastMinus = existingTag.lastIndexOf("-")
	def indexMajorNumber = existingTag.indexOf(".")
	def indexMinorNumber = existingTag.indexOf(".", indexMajorNumber + 1)
	def indexHotfixNumber = existingTag.indexOf(".", indexMinorNumber + 1)

	def buildNumber = existingTag.substring(indexHotfixNumber + 1).toInteger()
	def hotfixNumber = existingTag.substring(indexMinorNumber + 1, indexHotfixNumber).toInteger()
	def minorNumber = existingTag.substring(indexMajorNumber + 1, indexMinorNumber).toInteger()
	def majorNumber = existingTag.substring(indexLastMinus + 1, indexMajorNumber).toInteger()

	switch (buildType) {
		case "build": buildNumber++
			break
		case "hotfix": hotfixNumber++
			buildNumber = 0
			break
		case "minor": minorNumber++
			buildNumber = 0
			hotfixNumber = 0
			break
		case "major": majorNumber++
			buildNumber = 0
			hotfixNumber = 0
			minorNumber = 0
			break
		default: buildNumber++
	}

	def newTag = projectName + "-" + String.format('%02d', majorNumber) + "." + String.format('%02d', minorNumber) +
			"." + String.format('%02d', hotfixNumber) + "." + String.format('%02d', buildNumber)

	commonBuildPipeline.LOGGER('tag', "next version ${newTag} for build type ${buildType}")
	return newTag
}

// check app version validity
def checkAppVersionValidity(workspace, newversion) {
	def pomFile = 'pom.xml'
	if (commonBuildPipeline.MAVEN_POM_NAME.size() > 0) {
		pomFile = commonBuildPipeline.MAVEN_POM_NAME.replace('-f ', '')
	}
	def project = readMavenPom file: "${workspace}/${pomFile}"
	def oldversion = project.version
	def iNewVersion = newversion.replace("-SNAPSHOT", "").replaceAll("\\.", "").toInteger()
	def iOldVersion = oldversion.replace("-SNAPSHOT", "").replaceAll("\\.", "").toInteger()
	// new version must be greater than snapshot version
	commonBuildPipeline.LOGGER('app version', 'check app version')
	if (iNewVersion < iOldVersion) {
		error "version is not greater than the snapshot version (${newversion} < ${oldversion})"
	}
}

public sendReleaseEmail(projectName, releaseVersion, users) {
	// send release Email
	def emailBody = """A new release is deployed to the artifact repository: <b>${projectName} - ${releaseVersion}</b><br>"""
	emailext(
			subject: "Release Notification: ${projectName} - ${releaseVersion}",
			body: """
            <p>${emailBody}</p>
            """,
			to: users,
			mimeType: 'text/html'
	)
}

// archive artifacts
public saveArtifacts(projectName, branchName, buildInfoArtifactName) {
	stage('archive artifacts') {
		commonBuildPipeline.saveArtifacts(projectName, 'release', branchName, buildInfoArtifactName)
	}
}

public checkoutSource(gitUrl, branchName) {
	// overwrite the BRANCH_NAME attr with a branch name without `/`
	// because maven can not build with branch names with a `/` in it.
	// This override is needed elsewhere, but has to be set here!
	// ----
	env.BRANCH_NAME_ORIGINAL = BRANCH_NAME
	BRANCH_NAME = BRANCH_NAME.replaceAll('/', '_')
	// ----

	withCredentials([[$class: 'UsernamePasswordMultiBinding', credentialsId: 's-cicd-evoting', usernameVariable: 'GIT_USER', passwordVariable: 'GIT_PASS']]) {
		def url = gitUrl.replace('https://', '')
		sh "git clone https://${GIT_USER}:${GIT_PASS}@${url} ./"
		sh "git checkout ${branchName}"
	}

	sh 'git config user.email "spoc-dev-evoting@post.ch"'
	sh 'git config user.name "s-cicd-evoting, I226"'
}

return this