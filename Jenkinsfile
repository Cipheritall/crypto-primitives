#!groovy
/*
* Copyright 2014 by Swiss Post, Information Technology Services
*
*/

@Library('pipeline-library@master')_

def BUILD_INFO = Artifactory.newBuildInfo()
def PROJECT_NAME = 'crypto-primitives'
def GIT_END_URL = 'gitit.post.ch/scm/evotingecosystem/crypto-primitives.git'
def MAVEN_RELEASE_REPO = 'libs-release-evoting-local'
def MAVEN_SNAPSHOT_REPO = 'libs-snapshot-evoting-local'
def MAVEN_RESOLVE_REPO = 'maven-evoting-virtual'
def MAVEN_PARAMS = '-U --settings .mvn/settings.xml'

// Tools
def JDK = 'jdk-8u252'
def NODEJS = 'node-8.16.2'
def MAVEN = 'maven-3.6.3'

pipeline {

	agent {
		label 'apps-slaves-evoting'
	}

	options {
		disableConcurrentBuilds()
		buildDiscarder(logRotator(numToKeepStr:'10'))
		ansiColor('xterm')
		timestamps()
	}

	stages {

		stage('Informations') {
			steps {
				step([$class: 'StashNotifier'])
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
				branch 'develop'
			}
			steps {
				withEnv(["EVOTING_HOME=${env.WORKSPACE}"]) {
					mvnBuild(buildInfo: BUILD_INFO, mavenTool: MAVEN, mavenParams: MAVEN_PARAMS, releaseRepo: MAVEN_RELEASE_REPO, snapshotRepo: MAVEN_SNAPSHOT_REPO, resolveRepo: MAVEN_RESOLVE_REPO, deployArtifacts: 'true')
					publishBuildInformation(buildName: BUILD_NAME, buildInfo: BUILD_INFO)
				}
			}
		}

		stage('Sonar') {
            when {
				not {
					branch 'master'
				}
			}
			steps {
				withEnv(["EVOTING_HOME=${env.WORKSPACE}"]) {
					sh "mvn --settings ${EVOTING_HOME}/.mvn/settings.xml sonar:sonar"
				}
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
			script {
				step([$class: 'StashNotifier'])
			}
		}
		failure {
			sendBuildMail(projectName: PROJECT_NAME, message: 'Hi, the crypto-primitives build has failed!!', onError: true, toCommitters: true)
		}
	}
}