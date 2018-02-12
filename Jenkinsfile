node {
    stage('Checkout'){
        dir('src') {
            checkout scm
            sh 'git submodule update --init' 
        }
    }
    stage('Build!') {
        sh "src/scripts/test.sh"
    }
}