#!groovy
/*
* Copyright 2022 Post CH Ltd
*
*/

@Library('pipeline-library@master') _

def BUILD_INFO = Artifactory.newBuildInfo()
def PROJECT_NAME = 'crypto-primitives'
// Maven
def MAVEN_RELEASE_REPO = 'libs-release-evoting-local'
def MAVEN_SNAPSHOT_REPO = 'libs-snapshot-evoting-local'
def MAVEN_RESOLVE_REPO = 'maven-evoting-virtual'
def MAVEN_PARAMS = '-T 1.5C -U --settings .mvn/settings.xml --no-transfer-progress'

def PR_ID = env.BRANCH_NAME.replace('PR-', '')

// Tools
def MAVEN = 'maven-3'

pipeline {

	agent {
		label 'apps-slaves-evoting'
	}

	options {
		disableConcurrentBuilds()
		buildDiscarder(logRotator(numToKeepStr: '10'))
		ansiColor('xterm')
		timestamps()
	}

	tools {
		maven "${MAVEN}"
	}

	stages {

		stage('Prepare') {
			steps {
				step([$class: 'StashNotifier'])
				cleanWs()
				checkout scm
			}
		}

		stage('Infos logs') {
			steps {
				echo "--------------------------------- Build Information : ---------------------------------"
				echo "Build information : ${BUILD_INFO}"
				echo "Build name : ${BUILD_INFO.name}"
				echo "Build number : ${BUILD_INFO.number}"
				echo "Build starting date : ${BUILD_INFO.startDate}"
				echo "Maven version :"
				sh "mvn -v"
				echo "Java version :"
				sh "java -version"
				echo "Nodejs version :"
				sh "node -v"
				echo ""
				echo "---------------------------------------------------------------------------------------"
			}
		}
		stage('Build') {
			when {
				not {
					anyOf {
						branch 'develop'
						branch 'master'
                        branch 'hotfix/*'
					}
				}
			}
			steps {
				withEnv(["EVOTING_HOME=${env.WORKSPACE}"]) {
					mvnBuild(buildInfo: BUILD_INFO, mavenTool: MAVEN, mavenParams: MAVEN_PARAMS, releaseRepo: MAVEN_RELEASE_REPO, snapshotRepo: MAVEN_SNAPSHOT_REPO, resolveRepo: MAVEN_RESOLVE_REPO, deployArtifacts: 'false')
				}
			}
		}

		stage('Build and deploy') {
			environment {
				BUILD_NAME = getDefaultBuildName(projectName: PROJECT_NAME)
			}
			when {
				anyOf {
					branch 'develop'
					branch 'master'
                    branch 'hotfix/*'
				}
			}
			steps {
				withEnv(["EVOTING_HOME=${env.WORKSPACE}"]) {
					mvnBuild(buildInfo: BUILD_INFO, mavenTool: MAVEN, mavenParams: MAVEN_PARAMS, releaseRepo: MAVEN_RELEASE_REPO, snapshotRepo: MAVEN_SNAPSHOT_REPO, resolveRepo: MAVEN_RESOLVE_REPO, deployArtifacts: 'true')
				}
			}
		}


		stage('Sonar') {
			tools {
				jdk "jdk-11"
			}
			steps {
				script {
					withEnv(["EVOTING_HOME=${env.WORKSPACE}"]) {
						if (env.BRANCH_NAME.startsWith('PR-')) {
							sh "mvn --settings ${EVOTING_HOME}/.mvn/settings.xml sonar:sonar -Dsonar.projectName=${PROJECT_NAME} -Dsonar.pullrequest.key=${PR_ID} -Dsonar.pullrequest.branch=${env.CHANGE_BRANCH} -Dsonar.pullrequest.base=${env.CHANGE_TARGET}"
						} else {
							sh "mvn --settings ${EVOTING_HOME}/.mvn/settings.xml sonar:sonar -Dsonar.branch.name=$BRANCH_NAME"
						}
					}
				}
			}
		}


		stage('Publish build info') {
			when {
				anyOf {
					branch 'master'
					branch 'develop'
                    branch 'hotfix/*'
				}
			}
			environment {
				BUILD_NAME = getDefaultBuildName(projectName: PROJECT_NAME)

			}
			steps {
				publishBuildInformation(buildName: BUILD_NAME, buildInfo: BUILD_INFO)
			}
		}

		stage('Removal of .m2 directory on feature jobs') {
			when {
				not {
					anyOf {
						branch 'master'
						branch 'develop'
                        branch 'hotfix/*'
					}
				}
			}
			steps {
				sh "rm -rf .m2"
			}
		}
	}

	post {
		always {
			step([$class: 'StashNotifier'])
		}
		failure {
			sendBuildMail(projectName: PROJECT_NAME, message: 'Hi, the crypto-primitives build has failed!!', onError: true, toCommitters: true)

			script {
				if (env.BRANCH_NAME == 'master' || env.BRANCH_NAME == 'develop')
					office365ConnectorSend message: "**Jenkins build is broken:**<br> Check console output at $BUILD_URL to view the results.", webhookUrl: 'https://postchag.webhook.office.com/webhookb2/1b25b8a0-5358-4a0d-85a6-c619f1c215e0@3ae7c479-0cf1-47f4-8f84-929f364eff67/IncomingWebhook/b2af48935ba44042a6bd2b3d35444826/931ef1e6-141f-407b-bb51-90169ca9c9bf'
			}
		}
	}
}
