#get the current account number
data "aws_caller_identity" "current" {}


#create the role
resource "aws_iam_role" "s3_reader_role" {
  name = "s3_reader"
  assume_role_policy = jsonencode(
    {
      Version = "2012-10-17",
      Statement = [{
        Effect = "Allow",
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        },
        Action = "sts:AssumeRole"
      }]
    }
  )
}

resource "aws_iam_role_policy_attachment" "s3_reader_policy_attachment" {
  role = aws_iam_role.s3_reader_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}