class User < ApplicationRecord
  include Devise::JWT::RevocationStrategies::JTIMatcher
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable, :jwt_authenticatable, jwt_revocation_strategy: self

  #enum 
  enum role: {user: 0, admin: 1}    
  
  #set role as user cause admin will be generated in the seed
  before_save :set_default_role

  private

  def set_default_role
    self.role ||= :user
  end
end
