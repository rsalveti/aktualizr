node {
    stage('Checkout'){
        dir('src') {
            checkout scm
        }
    }
    stage('"Build!') {
        sh "scripts/test.sh"
    }
}