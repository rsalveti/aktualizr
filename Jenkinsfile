node {
    stage('Checkout'){
        dir('src') {
            checkout scm
            sh 'git submodule update --init' 
        }
    }
    stage('Build!') {
        sh "scripts/test.sh"
    }
}