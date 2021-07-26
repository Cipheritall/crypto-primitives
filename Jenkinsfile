#!groovy
/*
 * Copyright 2021 by Swiss Post, Information Technology Services
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

// Tools
def MAVEN = 'maven-3.6.3'

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
				}
			}
			steps {
				withEnv(["EVOTING_HOME=${env.WORKSPACE}"]) {
					mvnBuild(buildInfo: BUILD_INFO, mavenTool: MAVEN, mavenParams: MAVEN_PARAMS, releaseRepo: MAVEN_RELEASE_REPO, snapshotRepo: MAVEN_SNAPSHOT_REPO, resolveRepo: MAVEN_RESOLVE_REPO, deployArtifacts: 'true')
					publishBuildInformation(buildName: BUILD_NAME, buildInfo: BUILD_INFO)
				}
			}
		}

		stage('Sonar') {
			steps {
				withEnv(["EVOTING_HOME=${env.WORKSPACE}"]) {
					sh "mvn --settings ${EVOTING_HOME}/.mvn/settings.xml sonar:sonar -Dsonar.branch.name=$BRANCH_NAME"
				}
			}
		}


		stage('Publish build info') {
			when {
				anyOf {
					branch 'master'
					branch 'develop'
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
		}
	}
}