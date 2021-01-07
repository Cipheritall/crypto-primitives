pipeline {
    agent any
    parameters {
        string(name: 'status', defaultValue: 'FAILED', description: 'Build status to notify to Bitbucket')
        string(name: 'commit', defaultValue: '', description: 'Commit hash status to notify to Bitbucket')
    }
    stages {
        stage('Notify') {
            steps {
                script {
                    currentBuild.result = "${status}"
                }
            }
        }
    }
    post {
        always {
            step([$class: 'StashNotifier',
              commitSha1: "${commit}"])
        }
    }
}