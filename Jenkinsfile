node {
    stage('Checkout'){
        checkout scm
    }
    stage('"Build!') {
        sh "scripts/test.sh"
    }
}