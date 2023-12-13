pipeline {
  agent {
    docker {
      image 'rust:latest'
      args '-v /etc/passwd:/etc/passwd'
    }
  }
  stages {
    stage('Build') {
      steps {
          sshagent(credentials: ['playground']) {
          sh "cargo build"
    }
      }
    }

  }
}